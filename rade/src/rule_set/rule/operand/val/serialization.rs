use serde::{Deserialize, Serialize};

use super::{FieldInt, FieldStr, FieldStrList, Int, IntList, Str, StrList, Val};

#[derive(Debug, Deserialize, Serialize)]
enum ValSerialized {
    Int(u64),
    IntList(Vec<u64>),
    Str(String),
    StrList(Vec<String>),
    Field(FieldSerialized),
}

#[derive(Debug, Deserialize, Serialize)]
enum FieldSerialized {
    Pid,
    Tid,
    Session,
    RequestNumber,
    Content,
    AppName,
    FileName,
    ContentTokens,
}

impl<'de> serde::Deserialize<'de> for Val {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let val_helper = ValSerialized::deserialize(deserializer)?;
        Ok(Val::from(val_helper))
    }
}

impl From<ValSerialized> for Val {
    fn from(val_ser: ValSerialized) -> Self {
        match val_ser {
            ValSerialized::Int(i) => Val::Int(Int::Lit(i)),
            ValSerialized::IntList(v) => Val::IntList(IntList(v)),
            ValSerialized::Str(s) => Val::Str(Str::Lit(s.into())),
            ValSerialized::StrList(v) => {
                Val::StrList(StrList::Lit(v.into_iter().map(|s| s.into()).collect()))
            },
            ValSerialized::Field(field_ser) => match field_ser {
                FieldSerialized::Pid => Val::Int(Int::Field(FieldInt::Pid)),
                FieldSerialized::Tid => Val::Int(Int::Field(FieldInt::Tid)),
                FieldSerialized::Session => Val::Int(Int::Field(FieldInt::Session)),
                FieldSerialized::RequestNumber => Val::Int(Int::Field(FieldInt::RequestNumber)),
                FieldSerialized::Content => Val::Str(Str::Field(FieldStr::Content)),
                FieldSerialized::AppName => Val::Str(Str::Field(FieldStr::AppName)),
                FieldSerialized::FileName => Val::Str(Str::Field(FieldStr::FileName)),
                FieldSerialized::ContentTokens => {
                    Val::StrList(StrList::Field(FieldStrList::ContentTokens))
                },
            },
        }
    }
}
impl serde::Serialize for Val {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let val_ser = match self {
            Val::Int(Int::Lit(i)) => ValSerialized::Int(*i),
            Val::IntList(IntList(v)) => ValSerialized::IntList(v.clone()),
            Val::Str(Str::Lit(s)) => ValSerialized::Str(s.plain.clone()),
            Val::StrList(StrList::Lit(v)) => {
                ValSerialized::StrList(v.iter().map(|fs| fs.plain.clone()).collect())
            },
            Val::Int(Int::Field(f)) => ValSerialized::Field(match f {
                FieldInt::Pid => FieldSerialized::Pid,
                FieldInt::Tid => FieldSerialized::Tid,
                FieldInt::Session => FieldSerialized::Session,
                FieldInt::RequestNumber => FieldSerialized::RequestNumber,
            }),
            Val::Str(Str::Field(f)) => ValSerialized::Field(match f {
                FieldStr::Content => FieldSerialized::Content,
                FieldStr::AppName => FieldSerialized::AppName,
                FieldStr::FileName => FieldSerialized::FileName,
            }),
            Val::StrList(StrList::Field(f)) => ValSerialized::Field(match f {
                FieldStrList::ContentTokens => FieldSerialized::ContentTokens,
            }),
        };
        val_ser.serialize(serializer)
    }
}
