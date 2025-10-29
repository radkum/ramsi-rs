use std::io::read_to_string;

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use super::Rule;
use crate::Result;
#[derive(Deserialize, Serialize, Default, Debug)]
pub struct Rules(Vec<Rule>);
impl Rules {
    pub fn iter(&self) -> core::slice::Iter<'_, Rule> {
        self.0.iter()
    }

    pub fn add_rule(&mut self, rule: Rule) {
        self.0.push(rule);
    }

    #[cfg(feature = "std")]
    pub fn from_dir(path: &std::path::Path) -> Result<Self> {
        fn imp_from_dir(path: &std::path::Path, rules: &mut Rules) -> Result<()> {
            if path.is_file() {
                let mut file = std::fs::File::open(path)?;
                let content = read_to_string(&mut file)
                    .map_err(|err| anyhow!("Failed to read file {}: {:?}", path.display(), err))?;
                let rules_vec = serde_yaml_bw::from_str::<Rule>(&content)?;
                rules.add_rule(rules_vec);
            } else if path.is_dir() {
                let rules_dir = std::fs::read_dir(path)?;
                for rule_dir_entry in rules_dir {
                    let Ok(rule) = rule_dir_entry else {
                        log::warn!("Failed to read dir entry from path",);
                        continue;
                    };

                    if let Err(err) = imp_from_dir(&rule.path(), rules) {
                        println!(
                            "Failed to read rule from path: {:?}, error: {:?}",
                            rule.path(),
                            err
                        );
                    }
                }
            } else {
                Err(anyhow::anyhow!(
                    "Path {} is neither file nor directory",
                    path.display()
                ))?;
            }
            Ok(())
        }
        let mut rules = Rules::default();
        imp_from_dir(path, &mut rules)?;
        Ok(rules)
    }
}

impl From<Vec<Rule>> for Rules {
    fn from(rules: Vec<Rule>) -> Self {
        Self(rules)
    }
}
