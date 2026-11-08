//! P4.2B-4B: the Rust edge of the three-way block-structure parity triangle.
//!
//! `test/p42-vectors/chain/block_structure.json` is the shared corpus for three
//! independent implementations of rules B-3 through B-15:
//!
//! * the shipping Rust validator, [`Block::validate_structure`];
//! * the C++ port driven by `kernel/tools/p42_conformance.py`;
//! * the independent Python oracle in `test/harness/test_block_structure_verifier.py`.
//!
//! The other two legs already read that file. This file is the missing third leg.
//! It reads the *committed* corpus from disk at test runtime, rebuilds every
//! fixture's header, transaction list and seven-key validation context from that
//! fixture's own `input` block, and calls the production validator. The verdict is
//! whatever the shipping code returns; the fixture's `expected` side is only ever
//! a comparison target, never an input.
//!
//! Two deliberate non-features:
//!
//! * this is an integration test, so it cannot see `pub(crate)` items and no
//!   production file is touched to make it compile;
//! * `expected.violated_rules` is not compared. Producing that set would mean
//!   re-evaluating all thirteen guards here -- exactly the second implementation
//!   this milestone must not add. The precedence comparison instead uses the
//!   single row belonging to the variant the validator actually returned
//!   (`BlockError` -> row label below). That mapping is provenance metadata about
//!   which line of `validate_structure` produced the value, not a predicate, and
//!   it is the same mapping the C++ and Python legs already publish.
//!
//! Run:
//!   cargo +stable-x86_64-pc-windows-gnu test --test p42_block_structure_parity
//!   cargo +stable-x86_64-pc-windows-gnu test --test p42_block_structure_parity -- --nocapture

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use zerocoin::consensus::block::{Block, BlockError, BlockHeader};
use zerocoin::consensus::pow::{
    PowEngine, ScratchPadEngine, TrivialEngine, ENGINE_ID_SCRATCHPAD, ENGINE_ID_TRIVIAL,
};
use zerocoin::crypto::hash::{sha256, Hash256};
use zerocoin::ledger::transaction::Transaction;

// ---------------------------------------------------------------------------
// The corpus contract
// ---------------------------------------------------------------------------

/// How many fixtures the committed corpus publishes. Asserted, not assumed: a
/// fixture silently disappearing is a parity failure, not a smaller test run.
const EXPECTED_CASE_COUNT: usize = 37;

/// Every fixture id is this prefix plus a stable suffix. The manifest, the C++
/// harness and the Python verifier all key off the same string.
const GROUP: &str = "chain.block_structure.";

/// The only schema this reader understands.
const SCHEMA: &str = "zro-baseline-vectors/1";

fn corpus_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test")
        .join("p42-vectors")
        .join("chain")
        .join("block_structure.json")
}

fn manifest_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test")
        .join("p42-vectors")
        .join("manifest.json")
}

/// Read a JSON document from disk, failing loudly with the absolute path.
fn read_json(path: &Path) -> (String, Value) {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let parsed = serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
    (text, parsed)
}

fn cases_of<'a>(document: &'a Value, origin: &Path) -> &'a Vec<Value> {
    document["cases"]
        .as_array()
        .unwrap_or_else(|| panic!("{}: `cases` is not an array", origin.display()))
}

fn id_of(case: &Value) -> &str {
    case["id"]
        .as_str()
        .expect("every fixture publishes a string id")
}

// ---------------------------------------------------------------------------
// Rebuilding a digest from the fixture's published hex
// ---------------------------------------------------------------------------

/// The corpus publishes digests in their internal byte order as `internal_hex`
/// (the tagged header/merkle bytes as the ledger stores them) and, for
/// convenience, in explorer order as `display_hex`. `input.header.*_hex` and
/// `expected.*.internal_hex` are the same bytes, so they decode the same way.
fn digest(fixture_id: &str, field: &str, hex_text: &str) -> Hash256 {
    let bytes = hex::decode(hex_text)
        .unwrap_or_else(|error| panic!("{fixture_id}: {field} is not hex: {error}"));
    Hash256::from_slice(&bytes)
        .unwrap_or_else(|| panic!("{fixture_id}: {field} is not a 32-byte digest"))
}

fn integer(fixture_id: &str, field: &str, value: &Value) -> u64 {
    value
        .as_u64()
        .unwrap_or_else(|| panic!("{fixture_id}: {field} is not an unsigned integer"))
}

fn text<'a>(fixture_id: &str, field: &str, value: &'a Value) -> &'a str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("{fixture_id}: {field} is not a string"))
}

// ---------------------------------------------------------------------------
// Engine selection (G-3)
// ---------------------------------------------------------------------------

/// The ScratchPad presets the corpus is allowed to name, resolved through the
/// production constructors. The fixture publishes the constructor as a *symbol*
/// (`"ScratchPadEngine::balanced()"`), not as a pair of numbers: the exporter
/// deliberately keeps the engine budget out of the seven-key validation context
/// so the P4.1 reuse cases replay byte-identically. So the faithful reading of
/// "sourced from `engine_config`" is: resolve the published symbol through
/// production code, then re-enter the engine through the numeric constructor
/// with the numbers that production preset actually carries. Nothing here
/// restates 64 KiB or 1024, and an unknown symbol is an error rather than a
/// silent fall back to the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScratchPadPreset {
    Balanced,
    Mainnet,
    Mobile,
    LowSpec,
}

impl ScratchPadPreset {
    fn from_token(token: &str) -> Option<Self> {
        match token {
            "ScratchPadEngine::balanced()" => Some(Self::Balanced),
            "ScratchPadEngine::mainnet()" => Some(Self::Mainnet),
            "ScratchPadEngine::mobile()" => Some(Self::Mobile),
            "ScratchPadEngine::low_spec()" => Some(Self::LowSpec),
            _ => None,
        }
    }

    /// The production constructor for this preset. This is the only place a
    /// preset turns into a budget.
    fn construct(self) -> ScratchPadEngine {
        match self {
            Self::Balanced => ScratchPadEngine::balanced(),
            Self::Mainnet => ScratchPadEngine::mainnet(),
            Self::Mobile => ScratchPadEngine::mobile(),
            Self::LowSpec => ScratchPadEngine::low_spec(),
        }
    }

    const ALL: [Self; 4] = [Self::Balanced, Self::Mainnet, Self::Mobile, Self::LowSpec];
}

/// The engine a fixture selected, kept concrete so the test can inspect the
/// budget it resolved and the validator can borrow it as `&dyn PowEngine`.
#[derive(Debug, Clone, Copy)]
enum SelectedEngine {
    Trivial(TrivialEngine),
    ScratchPad(ScratchPadEngine),
}

impl SelectedEngine {
    fn as_pow(&self) -> &dyn PowEngine {
        match self {
            Self::Trivial(engine) => engine,
            Self::ScratchPad(engine) => engine,
        }
    }
}

fn require_named(fixture_id: &str, observed: &str, published: &str) -> Result<(), String> {
    if observed == published {
        Ok(())
    } else {
        Err(format!(
            "{fixture_id}: the fixture names engine `{published}` but the engine selected from \
             its own input is `{observed}`"
        ))
    }
}

/// Select the engine for one fixture from *its own published fields* and nothing
/// else. Every unsupported value is an explicit `Err`; there is no default arm
/// that quietly substitutes another engine.
fn select_engine(
    fixture_id: &str,
    engine_config: Option<&Value>,
    context_engine_name: &str,
) -> Result<SelectedEngine, String> {
    let Some(config) = engine_config else {
        // No `engine_config` object: the fixture is saying the trivial engine.
        // Cross-check that against the context it also publishes.
        let engine = TrivialEngine::new();
        require_named(fixture_id, engine.name(), context_engine_name)?;
        return Ok(SelectedEngine::Trivial(engine));
    };

    let published_id = integer(fixture_id, "engine_config.engine_id", &config["engine_id"]);
    let published_name = text(fixture_id, "engine_config.engine_name", &config["engine_name"]);
    let engine_id = u8::try_from(published_id).map_err(|_| {
        format!("{fixture_id}: engine_config.engine_id {published_id} does not fit the header's u8 field")
    })?;

    let selected = match engine_id {
        // Engine 0 uses the production trivial implementation and its real
        // semantics. A config object may describe it, but it may not describe it
        // as anything else.
        ENGINE_ID_TRIVIAL => {
            let engine = TrivialEngine::new();
            require_named(fixture_id, engine.name(), published_name)?;
            SelectedEngine::Trivial(engine)
        }
        ENGINE_ID_SCRATCHPAD => {
            let token = text(fixture_id, "engine_config.preset", &config["preset"]);
            let preset = ScratchPadPreset::from_token(token).ok_or_else(|| {
                format!(
                    "{fixture_id}: preset `{token}` is not a production ScratchPadEngine \
                     constructor; refusing to substitute another configuration"
                )
            })?;
            let configured = preset.construct();
            // Re-enter through the public numeric constructor with the budget the
            // production preset carries, so the engine this test validates with is
            // built by the same API a caller would use.
            let engine = ScratchPadEngine::new(configured.memory_bytes, configured.rounds);
            if engine.id() != engine_id {
                return Err(format!(
                    "{fixture_id}: engine_config.engine_id is {engine_id} but the resolved \
                     engine reports id {}",
                    engine.id()
                ));
            }
            require_named(fixture_id, engine.name(), published_name)?;
            SelectedEngine::ScratchPad(engine)
        }
        other => {
            return Err(format!(
                "{fixture_id}: engine id {other} is not an engine this corpus knows; \
                 refusing to substitute another engine"
            ))
        }
    };

    // The fixture publishes the engine name twice (once in `engine_config`, once
    // in `validation_context`). They must agree, and both must agree with the
    // engine actually selected, or the fixture is not self-consistent.
    require_named(fixture_id, selected.as_pow().name(), context_engine_name)?;
    Ok(selected)
}

// ---------------------------------------------------------------------------
// Rebuilding the validator's arguments from the fixture's `input`
// ---------------------------------------------------------------------------

struct ValidationContext {
    expected_chain: u32,
    expected_height: u64,
    expected_previous: Hash256,
    expected_bits: u32,
    median_time_past: u64,
    now: u64,
}

fn rebuild_header(fixture_id: &str, header: &Value) -> BlockHeader {
    BlockHeader {
        version: integer(fixture_id, "header.version", &header["version"]) as u32,
        chain: integer(fixture_id, "header.chain", &header["chain"]) as u32,
        height: integer(fixture_id, "header.height", &header["height"]),
        previous_hash: digest(
            fixture_id,
            "header.previous_hash_hex",
            text(fixture_id, "header.previous_hash_hex", &header["previous_hash_hex"]),
        ),
        merkle_root: digest(
            fixture_id,
            "header.merkle_root_hex",
            text(fixture_id, "header.merkle_root_hex", &header["merkle_root_hex"]),
        ),
        timestamp: integer(fixture_id, "header.timestamp", &header["timestamp"]),
        difficulty_bits: integer(fixture_id, "header.difficulty_bits", &header["difficulty_bits"])
            as u32,
        engine_id: integer(fixture_id, "header.engine_id", &header["engine_id"]) as u8,
        nonce: integer(fixture_id, "header.nonce", &header["nonce"]),
    }
}

fn rebuild_context(fixture_id: &str, context: &Value) -> ValidationContext {
    ValidationContext {
        expected_chain: integer(
            fixture_id,
            "validation_context.expected_chain",
            &context["expected_chain"],
        ) as u32,
        expected_height: integer(
            fixture_id,
            "validation_context.expected_height",
            &context["expected_height"],
        ),
        expected_previous: digest(
            fixture_id,
            "validation_context.expected_previous_hex",
            text(
                fixture_id,
                "validation_context.expected_previous_hex",
                &context["expected_previous_hex"],
            ),
        ),
        expected_bits: integer(
            fixture_id,
            "validation_context.expected_bits",
            &context["expected_bits"],
        ) as u32,
        median_time_past: integer(
            fixture_id,
            "validation_context.median_time_past",
            &context["median_time_past"],
        ),
        now: integer(fixture_id, "validation_context.now", &context["now"]),
    }
}

/// Decode one published transaction through the production decoder, then prove
/// the reconstruction is byte-exact by re-serializing with production code.
fn tx_from_hex(fixture_id: &str, hex_text: &str) -> Transaction {
    let bytes = hex::decode(hex_text)
        .unwrap_or_else(|error| panic!("{fixture_id}: a published transaction is not hex: {error}"));
    let tx = Transaction::deserialize(&bytes).unwrap_or_else(|error| {
        panic!("{fixture_id}: the production decoder rejects a published transaction: {error}")
    });
    let round_trip = hex::encode(tx.serialize());
    assert_eq!(
        round_trip, hex_text,
        "{fixture_id}: production re-serialization is not the published byte string"
    );
    tx
}

/// Two shapes exist in the corpus: a rich `transactions` array (each entry
/// publishes `serialized_hex`) for short lists, and a bare `transactions_hex`
/// string array for the two-thousand-transaction boundary cases. Both are
/// rebuilt through the same production decoder.
fn rebuild_transactions(fixture_id: &str, input: &Value) -> Vec<Transaction> {
    if let Some(entries) = input["transactions"].as_array() {
        return entries
            .iter()
            .map(|entry| {
                tx_from_hex(
                    fixture_id,
                    text(fixture_id, "transactions[].serialized_hex", &entry["serialized_hex"]),
                )
            })
            .collect();
    }
    let hexes = input["transactions_hex"]
        .as_array()
        .unwrap_or_else(|| panic!("{fixture_id}: input publishes neither `transactions` nor `transactions_hex`"));
    hexes
        .iter()
        .map(|entry| tx_from_hex(fixture_id, text(fixture_id, "transactions_hex[]", entry)))
        .collect()
}

// ---------------------------------------------------------------------------
// Reading the validator's answer
// ---------------------------------------------------------------------------

/// The evaluation row a variant belongs to. Rows are numbered by their order in
/// `Block::validate_structure`, which is the numbering the corpus, the manifest
/// and the C++ and Python legs all use. This is a label, not a guard: it says
/// which line returned the value, and it never decides whether the value was
/// correct.
fn row_of(error: &BlockError) -> u32 {
    match error {
        BlockError::WrongChain { .. } => 3,
        BlockError::BadHeight { .. } => 4,
        BlockError::BadPreviousHash => 5,
        BlockError::WrongEngine { .. } => 6,
        BlockError::BadDifficulty { .. } => 7,
        BlockError::NoTransactions => 8,
        BlockError::TooManyTransactions(_) => 9,
        BlockError::FirstNotCoinbase => 10,
        BlockError::DuplicateCoinbase => 11,
        BlockError::TimestampTooOld { .. } => 12,
        BlockError::TimestampTooFarFuture { .. } => 13,
        BlockError::RootMismatch => 14,
        BlockError::InsufficientProofOfWork => 15,
    }
}

fn kind_of(error: &BlockError) -> &'static str {
    match error {
        BlockError::WrongChain { .. } => "WrongChain",
        BlockError::BadHeight { .. } => "BadHeight",
        BlockError::BadPreviousHash => "BadPreviousHash",
        BlockError::RootMismatch => "RootMismatch",
        BlockError::WrongEngine { .. } => "WrongEngine",
        BlockError::BadDifficulty { .. } => "BadDifficulty",
        BlockError::InsufficientProofOfWork => "InsufficientProofOfWork",
        BlockError::TimestampTooOld { .. } => "TimestampTooOld",
        BlockError::TimestampTooFarFuture { .. } => "TimestampTooFarFuture",
        BlockError::NoTransactions => "NoTransactions",
        BlockError::FirstNotCoinbase => "FirstNotCoinbase",
        BlockError::DuplicateCoinbase => "DuplicateCoinbase",
        BlockError::TooManyTransactions(_) => "TooManyTransactions",
    }
}

fn payload_of(error: &BlockError) -> Value {
    match error {
        BlockError::WrongChain { expected, found } => {
            json!({ "expected": expected, "found": found })
        }
        BlockError::BadHeight { expected, found } => {
            json!({ "expected": expected, "found": found })
        }
        BlockError::WrongEngine { expected, found } => {
            json!({ "expected": expected, "found": found })
        }
        BlockError::BadDifficulty { expected, found } => {
            json!({ "expected": expected, "found": found })
        }
        BlockError::TimestampTooOld { median, found } => {
            json!({ "median": median, "found": found })
        }
        BlockError::TimestampTooFarFuture { now, found } => {
            json!({ "now": now, "found": found })
        }
        BlockError::TooManyTransactions(count) => json!({ "count": count }),
        _ => Value::Null,
    }
}

// ---------------------------------------------------------------------------
// One fixture, start to finish
// ---------------------------------------------------------------------------

/// What the shipping validator said about one reconstructed block.
struct Verdict {
    accepted: bool,
    error_kind: Value,
    error_payload: Value,
    reported_rule: Value,
    /// The root production computes over the rebuilt transactions, as internal
    /// hex. Used to prove the transaction list was reconstructed byte-exactly
    /// before the verdict is trusted.
    reconstructed_root_hex: String,
}

fn validate_fixture(case: &Value) -> Verdict {
    let fixture_id = id_of(case);
    let input = &case["input"];
    let engine_config = input.get("engine_config").filter(|value| !value.is_null());

    let header = rebuild_header(fixture_id, &input["header"]);
    let context = rebuild_context(fixture_id, &input["validation_context"]);
    let transactions = rebuild_transactions(fixture_id, input);

    // Reconstruction checks that need no consensus predicate: the fixture's own
    // count, and the digests the reference derived from the same byte strings.
    assert_eq!(
        integer(fixture_id, "tx_count", &input["tx_count"]) as usize,
        transactions.len(),
        "{fixture_id}: rebuilt {} transactions but the fixture published tx_count",
        transactions.len()
    );
    let reconstructed_root = Block::compute_merkle_root(&transactions);
    assert_eq!(
        hex::encode(reconstructed_root.0),
        text(
            fixture_id,
            "expected.computed_root.internal_hex",
            &case["expected"]["computed_root"]["internal_hex"]
        ),
        "{fixture_id}: `Block::compute_merkle_root` over the rebuilt transactions does not \
         reproduce the reference's published computed root"
    );
    assert_eq!(
        hex::encode(header.merkle_root.0),
        text(
            fixture_id,
            "expected.claimed_root.internal_hex",
            &case["expected"]["claimed_root"]["internal_hex"]
        ),
        "{fixture_id}: the rebuilt header does not carry the published claimed root"
    );

    let engine = select_engine(
        fixture_id,
        engine_config,
        text(
            fixture_id,
            "validation_context.engine",
            &input["validation_context"]["engine"],
        ),
    )
    .unwrap_or_else(|message| panic!("{message}"));

    let block = Block {
        header,
        transactions,
    };

    let outcome = block.validate_structure(
        engine.as_pow(),
        context.expected_chain,
        context.expected_height,
        &context.expected_previous,
        context.expected_bits,
        context.median_time_past,
        context.now,
    );

    let (error_kind, error_payload, reported_rule) = match &outcome {
        Ok(()) => (Value::Null, Value::Null, Value::Null),
        Err(error) => (
            Value::from(kind_of(error)),
            payload_of(error),
            json!(row_of(error)),
        ),
    };

    Verdict {
        accepted: outcome.is_ok(),
        error_kind,
        error_payload,
        reported_rule,
        reconstructed_root_hex: hex::encode(reconstructed_root.0),
    }
}

// ---------------------------------------------------------------------------
// G-2: the committed file, read from disk
// ---------------------------------------------------------------------------

/// The committed corpus on disk is what the test executes. This test makes that
/// visible instead of implicit: it prints the absolute path, the byte length and
/// the sha256 of the exact bytes parsed, so a run log shows the file that was
/// consumed. Everything after this point re-reads the same path independently.
///
/// Run with `-- --nocapture` to see the evidence line.
#[test]
fn the_parity_test_executes_the_committed_corpus_on_disk() {
    let path = corpus_path();
    assert!(
        path.is_file(),
        "the committed corpus is not on disk at {}",
        path.display()
    );

    let bytes = std::fs::read(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    assert!(!bytes.is_empty(), "{} is empty", path.display());
    assert_eq!(
        bytes.first(),
        Some(&b'{'),
        "{} does not begin a JSON object, so it is not the corpus",
        path.display()
    );

    let (text, document) = read_json(&path);
    assert_eq!(
        bytes.len(),
        text.len(),
        "{} changed between the raw read and the text read",
        path.display()
    );

    println!(
        "committed corpus: path={} bytes={} sha256={} cases={}",
        path.display(),
        bytes.len(),
        hex::encode(sha256(&bytes)),
        document["case_count"],
    );

    assert_eq!(
        document["schema"].as_str(),
        Some(SCHEMA),
        "{} is not a `{SCHEMA}` document",
        path.display()
    );
    assert_eq!(
        document["group"].as_str(),
        Some("chain.block_structure"),
        "{} is not the block-structure group",
        path.display()
    );
}

/// The corpus and the manifest it ships beside must describe the same 36
/// fixtures under the same identifiers. This is the stable-identifier check: a
/// renamed or dropped fixture fails here rather than quietly shrinking coverage.
#[test]
fn the_corpus_and_the_manifest_agree_on_every_fixture_identifier() {
    let path = corpus_path();
    let (_, corpus) = read_json(&path);
    let (_, manifest) = read_json(&manifest_path());

    let cases = cases_of(&corpus, &path);
    assert_eq!(
        corpus["case_count"].as_u64(),
        Some(EXPECTED_CASE_COUNT as u64),
        "the published `case_count` is not {EXPECTED_CASE_COUNT}"
    );
    assert_eq!(
        cases.len(),
        EXPECTED_CASE_COUNT,
        "the committed corpus holds {} fixtures, not {EXPECTED_CASE_COUNT}",
        cases.len()
    );
    assert_eq!(
        manifest["total_cases"].as_u64(),
        Some(EXPECTED_CASE_COUNT as u64),
        "the manifest's `total_cases` is not {EXPECTED_CASE_COUNT}"
    );

    let mut ids: Vec<&str> = cases.iter().map(id_of).collect();
    for id in &ids {
        assert!(
            id.starts_with(GROUP),
            "fixture id `{id}` is outside the `{GROUP}` group"
        );
    }
    let unique: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(
        unique.len(),
        ids.len(),
        "the corpus publishes duplicate fixture ids"
    );

    let manifest_ids: Vec<&str> = manifest["case_ids"]
        .as_array()
        .expect("the manifest publishes `case_ids`")
        .iter()
        .map(|value| value.as_str().expect("case_ids are strings"))
        .collect();
    ids.sort_unstable();
    let mut sorted_manifest = manifest_ids.clone();
    sorted_manifest.sort_unstable();
    assert_eq!(
        ids, sorted_manifest,
        "the corpus and the manifest do not name the same fixture identifiers"
    );
}

// ---------------------------------------------------------------------------
// G-1 + G-2: every fixture, validated by production code
// ---------------------------------------------------------------------------

/// All 36 committed fixtures, rebuilt from their own inputs and validated by
/// `Block::validate_structure`. Every assertion names the fixture id, so a
/// mismatch is attributable without re-running anything by hand.
#[test]
fn every_committed_fixture_matches_the_rust_validator() {
    let path = corpus_path();
    let (_, corpus) = read_json(&path);
    let cases = cases_of(&corpus, &path);
    assert_eq!(
        cases.len(),
        EXPECTED_CASE_COUNT,
        "expected {EXPECTED_CASE_COUNT} fixtures to exercise"
    );

    let mut accepted = 0usize;
    let mut rejected = 0usize;

    for case in cases {
        let fixture_id = id_of(case);
        let expected = &case["expected"];
        let verdict = validate_fixture(case);

        assert_eq!(
            verdict.accepted,
            expected["accepted"]
                .as_bool()
                .unwrap_or_else(|| panic!("{fixture_id}: expected.accepted is not a boolean")),
            "{fixture_id}: the validator's accept/reject verdict differs from the fixture"
        );
        assert_eq!(
            verdict.error_kind, expected["error_kind"],
            "{fixture_id}: the validator returned a different error variant"
        );
        assert_eq!(
            verdict.error_payload, expected["error_payload"],
            "{fixture_id}: the validator returned the right variant with a different payload"
        );
        assert_eq!(
            verdict.reported_rule, expected["reported_rule"],
            "{fixture_id}: the variant maps to a different `validate_structure` row than the \
             fixture publishes"
        );

        if verdict.accepted {
            accepted += 1;
            assert_eq!(
                verdict.reconstructed_root_hex,
                text(
                    fixture_id,
                    "expected.computed_root.internal_hex",
                    &expected["computed_root"]["internal_hex"]
                ),
                "{fixture_id}: an accepted block's reconstructed root is not the published one"
            );
        } else {
            rejected += 1;
        }
    }

    println!(
        "rust parity: {} fixtures exercised, {} accepted, {} rejected",
        EXPECTED_CASE_COUNT, accepted, rejected
    );
    assert_eq!(accepted + rejected, EXPECTED_CASE_COUNT);
    // The corpus publishes 7 accepted and 30 rejected cases. Pinning the split
    // catches a fixture flipping verdict without the count moving.
    assert_eq!(accepted, 7, "the corpus publishes seven accepted fixtures");
    assert_eq!(rejected, 30, "the corpus publishes thirty rejected fixtures");
}

/// The previous test would also pass if the adapter quietly copied
/// `expected.error_kind`. This one rules that out: it takes a committed fixture,
/// repairs one defect in its *input* in memory, and asserts the validator's
/// verdict moves to the next row -- while the fixture's `expected` side still
/// names the old one. Nothing in `test/p42-vectors/` is written; the mutation is
/// a detached `serde_json::Value`.
///
/// The fixture chosen is `pair_07_08_bits_and_empty`, whose only two defects are
/// a difficulty mismatch (row B-7) and an empty transaction list (row B-8).
/// `difficulty_bits` is part of the proof-of-work preimage, so rewriting it leaves
/// the header unmined; that is fine, because B-8 returns before B-15 is ever
/// reached. A field that is *not* re-committed could not be used here: every
/// header field but the nonce feeds the preimage.
#[test]
fn the_verdict_is_derived_from_the_input_not_copied_from_the_expected_side() {
    let path = corpus_path();
    let (_, corpus) = read_json(&path);
    let cases = cases_of(&corpus, &path);

    let original = cases
        .iter()
        .find(|case| id_of(*case).ends_with("pair_07_08_bits_and_empty"))
        .expect("the corpus publishes the bits-and-empty precedence fixture");

    let before = validate_fixture(original);
    assert!(!before.accepted, "the unmodified fixture must be rejected");
    assert_eq!(
        before.reported_rule,
        json!(7),
        "the unmodified fixture must be rejected at row B-7"
    );
    assert_eq!(before.error_kind, Value::from("BadDifficulty"));

    // Give the header the difficulty the context asks for. B-7 now passes, and
    // the empty transaction list is the next guard that fails.
    let mut perturbed = original.clone();
    let expected_bits = perturbed["input"]["validation_context"]["expected_bits"].clone();
    perturbed["input"]["header"]["difficulty_bits"] = expected_bits;

    let after = validate_fixture(&perturbed);
    assert!(!after.accepted, "the block is still empty, so it must still be rejected");
    assert_eq!(
        after.reported_rule,
        json!(8),
        "repairing B-7 in memory must expose row B-8, not leave the verdict at B-7"
    );
    assert_eq!(after.error_kind, Value::from("NoTransactions"));
    assert_ne!(
        after.reported_rule, before.reported_rule,
        "the verdict did not move, so it is not derived from the input"
    );

    // The fixture's own expected side was never touched and still names the old
    // verdict. If the adapter had read it, `after` would still say BadDifficulty.
    assert_eq!(
        perturbed["expected"]["reported_rule"].as_u64(),
        Some(7),
        "this test relies on the fixture's expected side still naming row B-7"
    );
    assert_eq!(
        perturbed["expected"]["error_kind"].as_str(),
        Some("BadDifficulty")
    );
}

// ---------------------------------------------------------------------------
// G-3: engine configuration fidelity
// ---------------------------------------------------------------------------

/// Every fixture's engine comes from its own published fields. This walks the
/// six scratchpad fixtures and asserts the budget they resolved is the one the
/// published preset names -- and that it was reached by resolving that token,
/// not by falling back to a default. "The one the published preset names" is
/// only a real constraint because the corpus now publishes more than one preset:
/// with a single preset, `construct()` and a hardcoded default would agree.
#[test]
fn every_scratchpad_fixture_resolves_the_preset_it_publishes() {
    let path = corpus_path();
    let (_, corpus) = read_json(&path);

    let mut scratchpad = 0usize;
    for case in cases_of(&corpus, &path) {
        let fixture_id = id_of(case);
        let input = &case["input"];
        let Some(config) = input.get("engine_config").filter(|value| !value.is_null()) else {
            continue;
        };

        let token = text(fixture_id, "engine_config.preset", &config["preset"]);
        let preset = ScratchPadPreset::from_token(token)
            .unwrap_or_else(|| panic!("{fixture_id}: corpus publishes unmodelled preset `{token}`"));
        let selected = select_engine(
            fixture_id,
            Some(config),
            text(
                fixture_id,
                "validation_context.engine",
                &input["validation_context"]["engine"],
            ),
        )
        .unwrap_or_else(|message| panic!("{message}"));

        let SelectedEngine::ScratchPad(engine) = selected else {
            panic!("{fixture_id}: engine_config names a scratchpad preset but a different engine was selected")
        };
        let configured = preset.construct();
        assert_eq!(
            (engine.memory_bytes, engine.rounds),
            (configured.memory_bytes, configured.rounds),
            "{fixture_id}: the selected scratchpad budget is not the published preset's budget"
        );
        scratchpad += 1;
    }

    assert_eq!(
        scratchpad, 6,
        "the corpus publishes six scratchpad fixtures; {} were resolved",
        scratchpad
    );
}

/// The G-3 negative control. A non-default preset must resolve to a *different*
/// budget than `balanced()`, which is what proves no fixture can be silently
/// served balanced parameters. `balanced()` is called here as production code;
/// no 64 KiB or 1024 is restated in this file.
#[test]
fn a_non_default_preset_is_not_coerced_to_balanced() {
    let balanced = ScratchPadEngine::balanced();
    let balanced_budget = (balanced.memory_bytes, balanced.rounds);

    let mut saw_non_default = 0usize;
    for preset in ScratchPadPreset::ALL {
        let configured = preset.construct();
        let rebuilt = ScratchPadEngine::new(configured.memory_bytes, configured.rounds);
        assert_eq!(
            (rebuilt.memory_bytes, rebuilt.rounds),
            (configured.memory_bytes, configured.rounds),
            "{preset:?}: re-entering the numeric constructor changed the budget"
        );
        if preset != ScratchPadPreset::Balanced {
            assert_ne!(
                (rebuilt.memory_bytes, rebuilt.rounds),
                balanced_budget,
                "{preset:?}: a non-default preset resolved to the balanced budget, which would \
                 make `balanced()` an accidental default"
            );
            saw_non_default += 1;
        }
    }
    assert_eq!(
        saw_non_default, 3,
        "only the balanced preset may share the balanced budget"
    );
}

/// The G-3 negative control for unknown inputs: an unmodelled preset symbol and
/// an unmodelled engine id must both be refused, never mapped to something else.
#[test]
fn an_unmodelled_engine_or_preset_is_refused_rather_than_substituted() {
    assert_eq!(
        ScratchPadPreset::from_token("ScratchPadEngine::nonexistent()"),
        None,
        "an unmodelled preset symbol must not resolve"
    );
    assert_eq!(
        ScratchPadPreset::from_token("balanced"),
        None,
        "a shortened preset symbol must not resolve by prefix or nickname"
    );

    let unknown_engine = json!({
        "engine_id": 7,
        "engine_name": "some-future-engine",
        "preset": "ScratchPadEngine::balanced()",
    });
    let refused = select_engine(
        "synthetic.unknown_engine",
        Some(&unknown_engine),
        "some-future-engine",
    );
    assert!(
        refused.is_err(),
        "engine id 7 must be refused, not mapped to the default engine"
    );

    let unknown_preset = json!({
        "engine_id": ENGINE_ID_SCRATCHPAD,
        "engine_name": "scratchpad-memory-hard",
        "preset": "ScratchPadEngine::hyper()",
    });
    let refused = select_engine(
        "synthetic.unknown_preset",
        Some(&unknown_preset),
        "scratchpad-memory-hard",
    );
    assert!(
        refused.is_err(),
        "an unmodelled scratchpad preset must be refused, not replaced by balanced"
    );

    // A config object that names the trivial engine but a scratchpad budget is
    // self-contradictory and must not be read as either one.
    let contradictory = json!({
        "engine_id": ENGINE_ID_TRIVIAL,
        "engine_name": "scratchpad-memory-hard",
        "preset": "ScratchPadEngine::balanced()",
    });
    let refused = select_engine(
        "synthetic.contradictory_config",
        Some(&contradictory),
        "scratchpad-memory-hard",
    );
    assert!(
        refused.is_err(),
        "engine id 0 with a scratchpad name must be refused"
    );
}

/// The corpus-backed form of the non-default probe above. P4.2B-4C added the
/// corpus's first non-default scratchpad witness (`mainnet()`) and P4.2B-4E the
/// second (`low_spec()`), so the resolver's non-default branch is now exercised
/// by committed data rather than only by synthetic controls -- and by two
/// *different* non-default budgets rather than one. Nothing here names a fixture
/// id: every witness is found through the preset token it publishes, and its
/// engine is rebuilt from that token with production constructors. The fixture's
/// `expected` side is compared, never read as an input -- so a consumer that
/// substituted `balanced()` for the named preset would show up as a nonce that
/// no longer meets its own target.
#[test]
fn the_committed_corpus_carries_a_non_default_scratchpad_witness() {
    let path = corpus_path();
    let (_, corpus) = read_json(&path);

    let balanced = ScratchPadEngine::balanced();
    let balanced_budget = (balanced.memory_bytes, balanced.rounds);

    // Pass one: every fixture that publishes an `engine_config` must resolve
    // through a production constructor, and two of them must carry a
    // configuration that differs from `balanced()`.
    let mut configured = 0usize;
    let mut non_default: Vec<(&str, ScratchPadPreset)> = Vec::new();
    for case in cases_of(&corpus, &path) {
        let fixture_id = id_of(case);
        let input = &case["input"];
        let Some(config) = input.get("engine_config").filter(|value| !value.is_null()) else {
            assert_eq!(
                text(
                    fixture_id,
                    "validation_context.engine",
                    &input["validation_context"]["engine"]
                ),
                TrivialEngine::new().name(),
                "{fixture_id}: no engine_config implies the trivial engine, but the fixture's \
                 context names a different one"
            );
            continue;
        };

        let token = text(fixture_id, "engine_config.preset", &config["preset"]);
        let preset = ScratchPadPreset::from_token(token)
            .unwrap_or_else(|| panic!("{fixture_id}: corpus publishes unmodelled preset `{token}`"));
        // The budget is reached by resolving the published token through the
        // production constructor, not by assuming whichever preset is default.
        let published = preset.construct();
        let selected = select_engine(
            fixture_id,
            Some(config),
            text(
                fixture_id,
                "validation_context.engine",
                &input["validation_context"]["engine"],
            ),
        )
        .unwrap_or_else(|message| panic!("{message}"));
        let SelectedEngine::ScratchPad(engine) = selected else {
            panic!("{fixture_id}: engine_config names a scratchpad preset but a different engine was selected")
        };
        assert_eq!(
            (engine.memory_bytes, engine.rounds),
            (published.memory_bytes, published.rounds),
            "{fixture_id}: the selected budget is not the published preset's budget"
        );

        configured += 1;
        if (engine.memory_bytes, engine.rounds) != balanced_budget {
            non_default.push((fixture_id, preset));
        }
    }

    assert_eq!(
        configured, 6,
        "the corpus publishes six engine_config fixtures; {configured} resolved"
    );
    assert_eq!(
        non_default.len(),
        2,
        "exactly two committed fixtures must witness a non-default scratchpad preset, found {:?}",
        non_default.iter().map(|(id, _)| *id).collect::<Vec<_>>()
    );

    // The two witnesses must be genuine witnesses of *different* presets: the
    // corpus has to carry `low_spec()` and not just a second copy of `mainnet()`,
    // and the two tokens must resolve to different budgets. Pinned here rather
    // than by fixture id, so renaming a case cannot make the pair vacuous.
    assert!(
        non_default.iter().any(|(_, preset)| *preset == ScratchPadPreset::LowSpec),
        "the corpus must witness `ScratchPadEngine::low_spec()`, found {:?}",
        non_default.iter().map(|(_, preset)| *preset).collect::<Vec<_>>()
    );
    let witness_budgets: std::collections::BTreeSet<(usize, usize)> = non_default
        .iter()
        .map(|(_, preset)| {
            let engine = preset.construct();
            (engine.memory_bytes, engine.rounds)
        })
        .collect();
    assert_eq!(
        witness_budgets.len(),
        non_default.len(),
        "two witnesses resolved to the same scratchpad budget, so one of them is not evidence \
         about the preset it names"
    );

    // Pass two: take each witness and prove the case is load-bearing rather than
    // merely labelled. Everything below reads only the fixture's own `input`.
    for (witness_id, preset) in non_default {
        assert_ne!(
            preset,
            ScratchPadPreset::Balanced,
            "{witness_id}: the witness resolved to the default preset"
        );
        let witness = cases_of(&corpus, &path)
            .iter()
            .find(|case| id_of(*case) == witness_id)
            .unwrap_or_else(|| panic!("{witness_id} disappeared from the corpus between passes"));
        let input = &witness["input"];
        let published = preset.construct();
        let configured_engine = ScratchPadEngine::new(published.memory_bytes, published.rounds);

        // The configuration really is non-default, stated against `balanced()` as
        // production code rather than against restated numbers.
        assert_ne!(
            (configured_engine.memory_bytes, configured_engine.rounds),
            balanced_budget,
            "{witness_id}: the selected preset publishes the balanced budget, so it is not a \
             non-default configuration"
        );

        // The header advertises the engine the fixture selects, which is what makes
        // B-6 a statement about this preset and lets B-15 be reached at all.
        assert_eq!(
            integer(witness_id, "header.engine_id", &input["header"]["engine_id"]),
            u64::from(configured_engine.id()),
            "{witness_id}: the header does not advertise the engine the fixture selects"
        );

        // The nonce is load-bearing: it solves the preset this fixture names and it
        // does not solve `balanced()`. If a consumer silently substituted the default
        // preset, this published nonce would fail -- which is what makes the case a
        // witness instead of a label.
        let header = rebuild_header(witness_id, &input["header"]);
        assert!(
            header.meets_own_target(&configured_engine),
            "{witness_id}: the published nonce does not solve the preset the fixture names"
        );
        assert!(
            !header.meets_own_target(&balanced),
            "{witness_id}: the published nonce also solves `balanced()`, so it is not evidence about \
             the preset the fixture names"
        );

        // The production validator accepts it under the engine it publishes.
        let verdict = validate_fixture(witness);
        assert!(
            verdict.accepted,
            "{witness_id}: the production validator rejects a fixture the corpus publishes as accepted"
        );
        assert_eq!(
            witness["expected"]["accepted"].as_bool(),
            Some(true),
            "{witness_id}: this test relies on the corpus publishing the witness as accepted"
        );
    }
}

// ---------------------------------------------------------------------------
// The ScratchPad digest itself, at the one point all three implementations
// publish
// ---------------------------------------------------------------------------

/// The probe the other two implementations pin their low-spec digest against:
/// the ASCII preimage `zerocoin-pow`, nonce 1, hashed at the `low_spec()`
/// budget. The corpus cannot carry this comparison. A fixture publishes a
/// verdict, and `proof_of_work_meets_target` only says the digest fell under a
/// threshold roughly half the space wide -- a digest function that had diverged
/// from the reference would still clear it about half the time. This test
/// therefore compares the digest itself, byte for byte, against the literal that
/// `kernel/tests/test_pow.cpp` (`kScratchLowSpec1`) and
/// `test/harness/test_low_spec_engine.py` both pin. It costs one 512 MiB hash and
/// is the only 512 MiB hash this file performs.
#[test]
fn the_low_spec_engine_reproduces_the_digest_the_other_two_implementations_pin() {
    const PREIMAGE: &[u8] = b"zerocoin-pow";
    const LOW_SPEC_PROBE: &str =
        "086fa583ae54a2d9fd3524497130ec2f97f50d81b5cc5cd824dc6979e5c36201";
    const BALANCED_PROBE: &str =
        "3efa396d1920fea0e3d7b942de423a5dd101e20a14eea042ecee4fd159997d1a";
    const MAINNET_PROBE: &str =
        "b0c6929750813bcb5280a5172f25583de55876eb9c70eb6b7c84a8cbda6fd9ec";

    let engine = ScratchPadEngine::low_spec();
    // Read off production code, so a mistyped budget in this test cannot agree
    // with a mistyped budget in the engine.
    assert_eq!(engine.memory_bytes, 512 * 1024 * 1024);
    assert_eq!(engine.rounds, 2_048);

    let observed = hex::encode(engine.hash(PREIMAGE, 1).0);
    assert_eq!(
        observed, LOW_SPEC_PROBE,
        "`low_spec()` at (`zerocoin-pow`, 1) does not reproduce the digest the Python oracle and \
         the C++ engine both pin"
    );

    // All three presets share `id()` and `name()`, so the digest is the only
    // thing that separates them. Reproducing either neighbour's digest would mean
    // the 512 MiB budget never reached the hash.
    assert_ne!(
        observed, BALANCED_PROBE,
        "`low_spec()` reproduced the `balanced()` digest"
    );
    assert_ne!(
        observed, MAINNET_PROBE,
        "`low_spec()` reproduced the `mainnet()` digest"
    );
}

// ---------------------------------------------------------------------------
// The documented precedence limitations, held to their own words
// ---------------------------------------------------------------------------

/// B-8 and B-9 cannot both hold for one block, so their relative order is not
/// observable and this test asserts no precedence for the pair. It is a
/// limitation the corpus itself records; the parity claim must not exceed it.
#[test]
fn b8_and_b9_are_never_violated_together_so_their_order_is_unobservable() {
    let path = corpus_path();
    let (_, corpus) = read_json(&path);

    for case in cases_of(&corpus, &path) {
        let fixture_id = id_of(case);
        let rules = case["expected"]["violated_rules"]
            .as_array()
            .unwrap_or_else(|| panic!("{fixture_id}: expected.violated_rules is not an array"));
        let has = |row: u64| rules.iter().any(|value| value.as_u64() == Some(row));
        assert!(
            !(has(8) && has(9)),
            "{fixture_id}: a block cannot be both empty and over the limit"
        );
    }

    let empty: Vec<&str> = cases_of(&corpus, &path)
        .iter()
        .filter(|case| case["input"]["tx_count"].as_u64() == Some(0))
        .map(id_of)
        .collect();
    assert_eq!(
        empty.len(),
        2,
        "the corpus publishes two empty-block fixtures, got {empty:?}"
    );
}

/// The precedence rows this corpus does pin. Each pair the manifest advertises
/// must be witnessed by a fixture whose published `reported_rule` is the earlier
/// row, and the validator must agree -- which the main parity test already
/// checks per fixture. This test states the coverage so a shrinking corpus fails
/// here rather than only in the manifest.
#[test]
fn every_advertised_adjacent_pair_has_a_fixture() {
    let path = corpus_path();
    let (_, corpus) = read_json(&path);
    let (_, manifest) = read_json(&manifest_path());

    let advertised: Vec<(u64, u64)> = manifest["precedence"]["adjacent_pairs_represented"]
        .as_array()
        .expect("the manifest publishes `precedence.adjacent_pairs_represented`")
        .iter()
        .map(|pair| {
            let pair = pair.as_array().expect("a pair is an array of two rows");
            (
                pair[0].as_u64().expect("a row number"),
                pair[1].as_u64().expect("a row number"),
            )
        })
        .collect();
    assert_eq!(advertised.len(), 11, "the manifest advertises eleven pairs");

    let cases = cases_of(&corpus, &path);
    for (lower, upper) in advertised {
        let prefix = format!("pair_{lower:02}_{upper:02}");
        let witness = cases
            .iter()
            .find(|case| id_of(*case).rsplit('.').next().unwrap_or("").starts_with(&prefix));
        let witness = witness.unwrap_or_else(|| panic!("no fixture witnesses the pair ({lower}, {upper})"));
        assert_eq!(
            witness["expected"]["reported_rule"].as_u64(),
            Some(lower),
            "{}: the witness for ({lower}, {upper}) does not report the earlier row",
            id_of(witness)
        );
        let rules: Vec<u64> = witness["expected"]["violated_rules"]
            .as_array()
            .expect("violated_rules is an array")
            .iter()
            .map(|value| value.as_u64().expect("a row number"))
            .collect();
        assert!(
            rules.contains(&lower) && rules.contains(&upper),
            "{}: the witness for ({lower}, {upper}) does not violate both rows",
            id_of(witness)
        );
    }
}
