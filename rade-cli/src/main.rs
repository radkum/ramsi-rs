mod utils;

use std::path::PathBuf;

use anyhow::anyhow;
use rade::*;
type Result<T> = core::result::Result<T, Box<dyn core::error::Error>>;

fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Trace)
        .init();
    utils::serialize_ruleset_from_dir()?;

    let events_path = PathBuf::from("rade/test_data/events");
    let events = Events::from_dir(&events_path).map_err(|err| {
        anyhow!(
            "Failed to load events from dir {}: {:?}",
            events_path.display(),
            err
        )
    })?;
    let rule_set = RuleSet::deserialize(&mut std::fs::File::open("rade/test_data/ruleset.bin")?)?;

    println!("Loaded {} events", events.iter().count());
    println!("Loaded {} rules", rule_set.rules().iter().count());
    let mut engine = RadeEngine::default();
    engine.load_rules(rule_set.retain_rules());

    let matches = engine.eval_bottom_up(events);
    println!("{:?}", matches);
    Ok(())
}
