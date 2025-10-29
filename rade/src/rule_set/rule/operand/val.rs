mod int;
mod int_list;
mod serialization;
mod str;
mod str_list;

pub use int::*;
pub use int_list::*;
pub use str::*;
pub use str_list::*;

use crate::{Event, InsensitiveFlag};

pub trait Eq {
    fn eq<'a>(
        &'a self,
        _elem: &Val,
        _event: &'a Event,
        _comp_flag: &Option<InsensitiveFlag>,
    ) -> bool {
        false
    }

    fn neq<'a>(
        &'a self,
        _elem: &Val,
        _event: &'a Event,
        _comp_flag: &Option<InsensitiveFlag>,
    ) -> bool {
        false
    }
}

pub trait Contains {
    fn contains<'a>(
        &'a self,
        _elem: &Val,
        _event: &'a Event,
        _comp_flag: &Option<InsensitiveFlag>,
    ) -> bool {
        false
    }
}

trait Cast {
    fn as_u64<'a>(&'a self, _event: &'a Event) -> Option<u64> {
        None
    }
    fn as_u64_list<'a>(&'a self, _event: &'a Event) -> Option<&'a Vec<u64>> {
        None
    }
    fn as_str<'a>(
        &'a self,
        _event: &'a Event,
        _comp_flag: &Option<InsensitiveFlag>,
    ) -> Option<&'a str> {
        None
    }
    fn as_str_list<'a>(
        &'a self,
        _event: &'a Event,
        _comp_flag: &Option<InsensitiveFlag>,
    ) -> Option<Vec<&'a str>> {
        None
    }
}

#[derive(Debug)]
pub enum Val {
    Int(Int),
    IntList(IntList),
    Str(Str),
    StrList(StrList),
}

impl Contains for Val {
    fn contains<'a>(&self, elem: &Val, event: &Event, flag: &Option<InsensitiveFlag>) -> bool {
        match self {
            Val::Int(val) => val.contains(elem, event, flag),
            Val::IntList(val) => val.contains(elem, event, flag),
            Val::Str(val) => val.contains(elem, event, flag),
            Val::StrList(val) => val.contains(elem, event, flag),
        }
    }
}

impl Eq for Val {
    fn eq<'a>(&'a self, elem: &Val, event: &'a Event, comp_flag: &Option<InsensitiveFlag>) -> bool {
        match self {
            Val::Int(int) => int.eq(elem, event, comp_flag),
            //Val::IntList(int_list) => int_list.eq(elem, event, comp_flag),
            Val::Str(str) => str.eq(elem, event, comp_flag),
            //Val::StrList(str_list) => str_list.eq(elem, event, comp_flag),
            _ => false,
        }
    }

    fn neq<'a>(
        &'a self,
        elem: &Val,
        event: &'a Event,
        comp_flag: &Option<InsensitiveFlag>,
    ) -> bool {
        match self {
            Val::Int(int) => int.neq(elem, event, comp_flag),
            //Val::IntList(int_list) => int_list.neq(elem, event, comp_flag),
            Val::Str(str) => str.neq(elem, event, comp_flag),
            //Val::StrList(str_list) => str_list.neq(elem, event, comp_flag),
            _ => false,
        }
    }
}

impl Cast for Val {
    fn as_u64<'a>(&'a self, event: &'a Event) -> Option<u64> {
        match self {
            Val::Int(int) => int.as_u64(event),
            Val::IntList(int) => int.as_u64(event),
            _ => None,
        }
    }

    fn as_str<'a>(
        &'a self,
        event: &'a Event,
        comp_flag: &Option<InsensitiveFlag>,
    ) -> Option<&'a str> {
        match self {
            Val::Str(str) => str.as_str(event, comp_flag),
            Val::StrList(str) => str.as_str(event, comp_flag),
            _ => None,
        }
    }

    fn as_u64_list<'a>(&'a self, event: &'a Event) -> Option<&'a Vec<u64>> {
        match self {
            Val::Int(i) => i.as_u64_list(event),
            Val::IntList(i) => i.as_u64_list(event),
            _ => None,
        }
    }

    fn as_str_list<'a>(
        &'a self,
        event: &'a Event,
        comp_flag: &Option<InsensitiveFlag>,
    ) -> Option<Vec<&'a str>> {
        match self {
            Val::Str(s) => s.as_str_list(event, comp_flag),
            Val::StrList(s) => s.as_str_list(event, comp_flag),
            _ => None,
        }
    }
}
