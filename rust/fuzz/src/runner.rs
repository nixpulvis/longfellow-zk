//! Shared LibAFL setup for every target.
//!
//! Every target binary declares a [`Target`] and calls [`main`]. The same
//! binary can run in several modes so that byte-level and grammar-based
//! fuzzing are compared with identical scheduling, feedback and objectives:
//!
//! - `bytes`: havoc + token mutations on raw bytes
//! - `bytes-cmplog`: `bytes` plus a cmplog tracing stage and I2S replacement
//! - `arbitrary`: the bytes engine driving a structure-aware harness that
//!   decodes its input with `arbitrary::Unstructured`
//! - `nautilus`: grammar-based generation and tree mutations
//!
//! All modes use the same coverage map (8-bit counters on longfellow crates
//! only), the same minimizing queue scheduler, crash + timeout objectives,
//! and write the same `stats.csv` time series.

// LibAFL 0.16 deprecates `AsSlice` and the executor `with_timeout`
// constructor, but the suggested replacements are not drop-in yet.
#![allow(deprecated)]

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    marker::PhantomData,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use clap::{Parser, ValueEnum};
use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::SimpleRestartingEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind, ShadowExecutor},
    feedback_or, feedback_or_fast,
    feedbacks::{
        CrashFeedback, MapFeedbackMetadata, MaxMapFeedback, NautilusChunksMetadata,
        NautilusFeedback, TimeFeedback, TimeoutFeedback,
    },
    fuzzer::{Evaluator, Fuzzer, StdFuzzer},
    generators::{NautilusContext, NautilusGenerator, RandBytesGenerator},
    inputs::{BytesInput, HasTargetBytes, Input, NautilusInput},
    monitors::SimpleMonitor,
    mutators::{
        havoc_mutations, tokens_mutations, HavocScheduledMutator, I2SRandReplace,
        NautilusRandomMutator, NautilusRecursionMutator, NautilusSpliceMutator, Tokens,
    },
    observers::{CanTrack, HitcountsIterableMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{Restartable, ShadowTracingStage, Stage, StdMutationalStage},
    state::{HasCorpus, HasExecutions, HasSolutions, StdState, Stoppable},
    Error, HasMetadata, HasNamedMetadata,
};
use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, Merge},
    AsSlice,
};
use libafl_targets::{counters_maps_observer, CmpLogObserver};

const EDGES: &str = "edges";

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    Bytes,
    BytesCmplog,
    Arbitrary,
    Nautilus,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Bytes => "bytes",
            Mode::BytesCmplog => "bytes-cmplog",
            Mode::Arbitrary => "arbitrary",
            Mode::Nautilus => "nautilus",
        }
    }
}

#[derive(Parser, Debug, Clone)]
pub struct Cli {
    /// Fuzzing engine / input representation.
    #[arg(long, value_enum, default_value_t = Mode::Bytes)]
    pub mode: Mode,
    /// Output root. The run writes to `<out>/<target>/<mode>[-<tag>]/`.
    #[arg(long, default_value = "out")]
    pub out: PathBuf,
    /// Extra label for the run directory (e.g. a trial number).
    #[arg(long)]
    pub tag: Option<String>,
    /// Stop after this many seconds (0 = run until killed).
    #[arg(long, default_value_t = 0)]
    pub seconds: u64,
    /// RNG seed (defaults to the current time).
    #[arg(long)]
    pub seed: Option<u64>,
    /// Per-execution timeout [default: the target's, 2000 unless it sets one].
    #[arg(long)]
    pub timeout_ms: Option<u64>,
    /// Ignore the target's seed corpus and start from generated inputs.
    #[arg(long)]
    pub no_seeds: bool,
    /// Seconds between rows in stats.csv.
    #[arg(long, default_value_t = 5)]
    pub stats_every: u64,
    /// Nautilus: maximum tree size.
    #[arg(long, default_value_t = 1000)]
    pub max_tree: usize,
    /// Run these inputs once each (no fuzzing) and exit. Crashes reproduce
    /// as a normal panic/abort with a backtrace.
    #[arg(long, num_args = 1..)]
    pub replay: Vec<PathBuf>,
    /// With --replay in nautilus mode: print the unparsed grammar output.
    #[arg(long)]
    pub print: bool,
    /// Write the grammar rules for this target to stdout and exit.
    #[arg(long)]
    pub dump_grammar: bool,
}

/// A fuzz target. Each binary in `src/bin/` builds one of these.
pub struct Target {
    pub name: &'static str,
    /// Harness for `bytes` and `bytes-cmplog`.
    pub bytes: Option<fn(&[u8])>,
    /// Harness for `arbitrary` (decodes with `arbitrary::Unstructured`).
    pub arbitrary: Option<fn(&[u8])>,
    /// Grammar and harness for `nautilus`. The harness receives the
    /// unparsed grammar output.
    pub nautilus: Option<(fn() -> crate::grammar::Grammar, fn(&[u8]))>,
    /// Seed inputs for `bytes` / `bytes-cmplog`.
    pub seeds: fn() -> Vec<Vec<u8>>,
    /// Byte-fuzzer dictionary.
    pub tokens: fn() -> Vec<Vec<u8>>,
    /// Called once before forking, to build expensive fixtures so that
    /// restarted children inherit them.
    pub setup: fn(),
    /// Default per-execution timeout, for targets whose ordinary inputs are
    /// slow. `--timeout-ms` overrides it.
    pub timeout_ms: u64,
}

impl Default for Target {
    fn default() -> Self {
        Self {
            name: "unnamed",
            bytes: None,
            arbitrary: None,
            nautilus: None,
            seeds: Vec::new,
            tokens: Vec::new,
            setup: || {},
            timeout_ms: 2000,
        }
    }
}

pub fn main(target: Target) {
    let mut cli = Cli::parse();
    cli.timeout_ms.get_or_insert(target.timeout_ms);

    if cli.dump_grammar {
        let (grammar, _) = target.nautilus.expect("this target has no grammar");
        print!("{}", grammar().dump());
        return;
    }

    (target.setup)();

    if !cli.replay.is_empty() {
        replay(&target, &cli);
        return;
    }

    let dir = run_dir(&target, &cli);
    fs::create_dir_all(&dir).expect("create run dir");
    eprintln!("[{}] mode={} out={}", target.name, cli.mode.name(), dir.display());

    check_instrumented();

    let res = match cli.mode {
        Mode::Bytes | Mode::BytesCmplog => {
            let h = target
                .bytes
                .unwrap_or_else(|| panic!("{} has no bytes harness", target.name));
            let seeds = if cli.no_seeds { Vec::new() } else { (target.seeds)() };
            fuzz_bytes(&cli, &dir, h, seeds, (target.tokens)(), cli.mode == Mode::BytesCmplog)
        }
        Mode::Arbitrary => {
            let h = target
                .arbitrary
                .unwrap_or_else(|| panic!("{} has no arbitrary harness", target.name));
            fuzz_bytes(&cli, &dir, h, Vec::new(), Vec::new(), false)
        }
        Mode::Nautilus => {
            let (grammar, h) = target
                .nautilus
                .unwrap_or_else(|| panic!("{} has no grammar", target.name));
            // Mutators borrow the context for the lifetime of the fuzzer.
            let ctx: &'static NautilusContext = Box::leak(Box::new(grammar().context(cli.max_tree)));
            fuzz_nautilus(&cli, &dir, ctx, h)
        }
    };
    match res {
        Ok(()) | Err(Error::ShuttingDown) => {}
        Err(e) => panic!("fuzzer failed: {e:?}"),
    }
}

fn run_dir(target: &Target, cli: &Cli) -> PathBuf {
    let mut leaf = cli.mode.name().to_string();
    if let Some(tag) = &cli.tag {
        leaf.push('-');
        leaf.push_str(tag);
    }
    cli.out.join(target.name).join(leaf)
}

fn check_instrumented() {
    // SAFETY: read-only access to the registry populated by sancov ctors.
    let maps = unsafe { &*libafl_targets::sancov_8bit::counters_maps_ptr() };
    let total: usize = maps.iter().map(|m| m.as_slice().len()).sum();
    if total == 0 {
        eprintln!(
            "error: no coverage counters registered. Build with scripts/build.sh so \
             longfellow crates are instrumented."
        );
        std::process::exit(2);
    }
    eprintln!("coverage: {} modules, {} counters", maps.len(), total);
}

fn replay(target: &Target, cli: &Cli) {
    let ctx = (cli.mode == Mode::Nautilus).then(|| {
        let (grammar, _) = target.nautilus.expect("this target has no grammar");
        grammar().context(cli.max_tree)
    });
    for path in &cli.replay {
        eprintln!("replaying {}", path.display());
        match cli.mode {
            Mode::Bytes | Mode::BytesCmplog => {
                (target.bytes.unwrap())(&read_input_bytes(path));
            }
            Mode::Arbitrary => (target.arbitrary.unwrap())(&read_input_bytes(path)),
            Mode::Nautilus => {
                let input = NautilusInput::from_file(path).expect("read nautilus input");
                let mut text = Vec::new();
                input.unparse(ctx.as_ref().unwrap(), &mut text);
                if cli.print {
                    println!("{}", String::from_utf8_lossy(&text));
                }
                (target.nautilus.unwrap().1)(&text);
            }
        }
    }
    eprintln!("replayed {} inputs without crashing", cli.replay.len());
}

/// Corpus files are serialized `BytesInput`s; accept raw files too.
fn read_input_bytes(path: &Path) -> Vec<u8> {
    match BytesInput::from_file(path) {
        Ok(i) => i.target_bytes().as_slice().to_vec(),
        Err(_) => fs::read(path).expect("read input"),
    }
}

/// Appends a row to `stats.csv` every `every` and stops the fuzzer at the
/// deadline. Reading the map feedback's own metadata means "edges" is exactly
/// what the fuzzer considers covered, in every mode.
pub struct StatsStage<I> {
    path: PathBuf,
    every: Duration,
    last: Option<Instant>,
    start: SystemTime,
    deadline: Option<SystemTime>,
    total_edges: usize,
    phantom: PhantomData<I>,
}

impl<I> StatsStage<I> {
    fn new(dir: &Path, cli: &Cli, start: SystemTime, total_edges: usize) -> Self {
        let path = dir.join("stats.csv");
        if !path.exists() {
            fs::write(
                &path,
                "unix_ms,elapsed_s,execs,corpus,solutions,edges,edges_total\n",
            )
            .expect("write stats header");
        }
        Self {
            path,
            every: Duration::from_secs(cli.stats_every.max(1)),
            last: None,
            start,
            deadline: (cli.seconds > 0).then(|| start + Duration::from_secs(cli.seconds)),
            total_edges,
            phantom: PhantomData,
        }
    }

    fn row<S>(&self, state: &S) -> String
    where
        S: HasExecutions + HasCorpus<I> + HasSolutions<I> + HasNamedMetadata,
    {
        let now = SystemTime::now();
        let covered = state
            .named_metadata::<MapFeedbackMetadata<u8>>(EDGES)
            .map(|m| m.num_covered_map_indexes)
            .unwrap_or(0);
        format!(
            "{},{:.1},{},{},{},{},{}\n",
            now.duration_since(UNIX_EPOCH).unwrap().as_millis(),
            now.duration_since(self.start).unwrap_or_default().as_secs_f64(),
            state.executions(),
            state.corpus().count(),
            state.solutions().count(),
            covered,
            self.total_edges,
        )
    }
}

impl<E, EM, I, S, Z> Stage<E, EM, S, Z> for StatsStage<I>
where
    S: HasExecutions + HasCorpus<I> + HasSolutions<I> + HasNamedMetadata + Stoppable,
{
    fn perform(&mut self, _: &mut Z, _: &mut E, state: &mut S, _: &mut EM) -> Result<(), Error> {
        let due = self.last.map_or(true, |t| t.elapsed() >= self.every);
        let past_deadline = self.deadline.is_some_and(|d| SystemTime::now() >= d);
        if due || past_deadline {
            self.last = Some(Instant::now());
            let mut f = OpenOptions::new().append(true).open(&self.path)?;
            f.write_all(self.row(state).as_bytes())?;
        }
        if past_deadline {
            state.request_stop();
        }
        Ok(())
    }
}

impl<I, S> Restartable<S> for StatsStage<I> {
    fn should_restart(&mut self, _: &mut S) -> Result<bool, Error> {
        Ok(true)
    }
    fn clear_progress(&mut self, _: &mut S) -> Result<(), Error> {
        Ok(())
    }
}

fn total_edges() -> usize {
    // SAFETY: read-only access to the sancov counter registry.
    let maps = unsafe { &*libafl_targets::sancov_8bit::counters_maps_ptr() };
    maps.iter().map(|m| m.as_slice().len()).sum()
}

fn seed_rand(cli: &Cli) -> StdRand {
    StdRand::with_seed(cli.seed.unwrap_or_else(current_nanos))
}

fn monitor() -> SimpleMonitor<impl FnMut(&str)> {
    SimpleMonitor::new(|s| eprintln!("{s}"))
}

fn fuzz_bytes(
    cli: &Cli,
    dir: &Path,
    harness_fn: fn(&[u8]),
    seeds: Vec<Vec<u8>>,
    tokens: Vec<Vec<u8>>,
    cmplog: bool,
) -> Result<(), Error> {
    // Captured before the fork so restarted children share one clock.
    let start = SystemTime::now();
    let mut shmem_provider = StdShMemProvider::new()?;
    let (state, mut mgr) =
        SimpleRestartingEventManager::launch(monitor(), &mut shmem_provider, true)?;

    // SAFETY: the counters maps are registered by sancov module ctors before
    // main and live for the whole process.
    let edges = unsafe { counters_maps_observer(EDGES) };
    let edges = HitcountsIterableMapObserver::new(edges).track_indices();
    let time = TimeObserver::new("time");

    let mut feedback = feedback_or!(MaxMapFeedback::new(&edges), TimeFeedback::new(&time));
    let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            seed_rand(cli),
            InMemoryOnDiskCorpus::<BytesInput>::new(dir.join("queue")).unwrap(),
            OnDiskCorpus::new(dir.join("crashes")).unwrap(),
            &mut feedback,
            &mut objective,
        )
        .unwrap()
    });
    if !tokens.is_empty() && state.metadata_map().get::<Tokens>().is_none() {
        state.add_metadata(Tokens::from(tokens));
    }

    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges, QueueScheduler::new());
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut harness = |input: &BytesInput| {
        let buf = input.target_bytes();
        harness_fn(buf.as_slice());
        ExitKind::Ok
    };
    let timeout = Duration::from_millis(cli.timeout_ms.unwrap());
    let stats = StatsStage::<BytesInput>::new(dir, cli, start, total_edges());
    let mutator = HavocScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));

    macro_rules! seed_corpus {
        ($executor:expr) => {
            if state.corpus().count() == 0 {
                if seeds.is_empty() {
                    let mut generator = RandBytesGenerator::new(core::num::NonZero::new(64).unwrap());
                    state.generate_initial_inputs_forced(
                        &mut fuzzer, $executor, &mut generator, &mut mgr, 32,
                    )?;
                } else {
                    for s in &seeds {
                        fuzzer.add_input(&mut state, $executor, &mut mgr, BytesInput::new(s.clone()))?;
                    }
                }
                eprintln!("initial corpus: {}", state.corpus().count());
            }
        };
    }

    if cmplog {
        let cmplog_observer = CmpLogObserver::new("cmplog", true);
        let executor = InProcessExecutor::with_timeout(
            &mut harness,
            tuple_list!(edges, time),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            timeout,
        )?;
        let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));
        seed_corpus!(&mut executor);
        let i2s = StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(I2SRandReplace::new())));
        let mut stages = tuple_list!(
            ShadowTracingStage::new(),
            i2s,
            StdMutationalStage::new(mutator),
            stats
        );
        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
    } else {
        let mut executor = InProcessExecutor::with_timeout(
            &mut harness,
            tuple_list!(edges, time),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            timeout,
        )?;
        seed_corpus!(&mut executor);
        let mut stages = tuple_list!(StdMutationalStage::new(mutator), stats);
        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
    }
}

fn fuzz_nautilus(
    cli: &Cli,
    dir: &Path,
    ctx: &'static NautilusContext,
    harness_fn: fn(&[u8]),
) -> Result<(), Error> {
    let start = SystemTime::now();
    let mut shmem_provider = StdShMemProvider::new()?;
    let (state, mut mgr) =
        SimpleRestartingEventManager::launch(monitor(), &mut shmem_provider, true)?;

    // SAFETY: see fuzz_bytes.
    let edges = unsafe { counters_maps_observer(EDGES) };
    let edges = HitcountsIterableMapObserver::new(edges).track_indices();
    let time = TimeObserver::new("time");

    let mut feedback = feedback_or!(
        MaxMapFeedback::new(&edges),
        TimeFeedback::new(&time),
        NautilusFeedback::new(ctx)
    );
    let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            seed_rand(cli),
            InMemoryOnDiskCorpus::<NautilusInput>::new(dir.join("queue")).unwrap(),
            OnDiskCorpus::new(dir.join("crashes")).unwrap(),
            &mut feedback,
            &mut objective,
        )
        .unwrap()
    });
    if state.metadata_map().get::<NautilusChunksMetadata>().is_none() {
        let chunks = dir.join("chunks");
        fs::create_dir_all(&chunks)?;
        state.add_metadata(NautilusChunksMetadata::new(chunks.to_string_lossy().into_owned()));
    }

    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges, QueueScheduler::new());
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut text = Vec::with_capacity(4096);
    let mut harness = |input: &NautilusInput| {
        text.clear();
        input.unparse(ctx, &mut text);
        harness_fn(&text);
        ExitKind::Ok
    };
    let mut executor = InProcessExecutor::with_timeout(
        &mut harness,
        tuple_list!(edges, time),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        Duration::from_millis(cli.timeout_ms.unwrap()),
    )?;

    if state.corpus().count() == 0 {
        let mut generator = NautilusGenerator::new(ctx);
        state.generate_initial_inputs_forced(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 32)?;
        eprintln!("initial corpus: {}", state.corpus().count());
    }

    let mutator = HavocScheduledMutator::with_max_stack_pow(
        tuple_list!(
            NautilusRandomMutator::new(ctx),
            NautilusRandomMutator::new(ctx),
            NautilusRandomMutator::new(ctx),
            NautilusRandomMutator::new(ctx),
            NautilusRandomMutator::new(ctx),
            NautilusRandomMutator::new(ctx),
            NautilusRecursionMutator::new(ctx),
            NautilusSpliceMutator::new(ctx),
            NautilusSpliceMutator::new(ctx),
            NautilusSpliceMutator::new(ctx),
        ),
        2,
    );
    let stats = StatsStage::<NautilusInput>::new(dir, cli, start, total_edges());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator), stats);
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
}

