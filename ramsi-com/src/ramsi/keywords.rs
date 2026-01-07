use macros::lowercase_const_array;
use macros::compile_sha256_set;
use phf::phf_set;

lowercase_const_array! {
pub(super) const BLACKLIST_KEYWORDS: &[&str] = [
    "amsi.dll",
    "amsiInitFailed",
    "AMSI/Providers/",
    "AMSI/Providers/",
    "AMSI/Providers\\",
    "AMSI\\Providers",
    "AMSI\\Providers/",
    "AMSI\\Providers\\",
    "AmsiEnable",
    "AmsiScanBuffer",
    "AmsiUtils",
    "Invoke-Mimikatz",
    "System.Management.Automation.AmsiUtils",
    "System.Management.Automation.Utils",
];
}

lowercase_const_array! {
pub(super) const BLACKLIST_KEYWORDS_ENDSWITH: &[&str] = &[
    "amsi.dll",
];
}

lowercase_const_array! {
pub(super) const BLACKLIST_FUNCTIONS: &[&str] = &[
    "AmsiInitialize",
];
}

compile_sha256_set! {
pub(super) const CLEANLIST_SHA256_SET: &[&str] = &[
    "cf07194ee232eb531e15f690000d19846dea69cf05504782658afcfacb9228a2",
];
}

lowercase_const_array! {
pub(super) const TELEMETRY_TYPES: &[&str] = &[
    "Reflection.Assembly",
    "System.Management.Automation.PSTypeName",
];
}

lowercase_const_array! {
pub(super) const TELEMETRY_STRINGS: &[&str] = &[
    "clr.dll",
    "GetModuleHandle",
    "GetProcAddress",
    "Microsoft.Win32.UnsafeNativeMethods",
    "System.Reflection.BindingFlags",
    "System.dll",
];
}

lowercase_const_array! {
pub(super) const TELEMETRY_FUNCTIONS: &[&str] = &[
    "Add-Type",
    "Alloc",
    "Base64",
    "Bypass",
    "Create",
    "Crypto",
    "Cryptor",
    "Define",
    "Deflatestream",
    "Dllimport",
    "Dynamicassembly",
    "Emit",
    "Encodedcommand",
    "Execute",
    "Expandstring",
    "Free",
    "Frombase64string",
    "GetAssemblies",
    "GetAsyncKeyState",
    "GetConstructor",
    "GetMethod",
    "GetModule",
    "GetType",
    "Iex",
    "Invoke",
    "IoControl",
    "Method",
    "Privileges",
    "RemoteThread",
    "Run",
    "Security",
    "Start",
    "Token",
    "Virtual",
];
}

#[cfg(test)]
mod tests {
    use hex::FromHex;
    use super::*;

    lowercase_const_array! {
        const LOWERCASED: &[&str] = &[
            "AMSI\\Providers\\",
            "AmsiEnable",
            "AmsiScanBuffer",
            "AmsiUtils",
            "Invoke-Mimikatz",
            "System.Management.Automation.AmsiUtils",
            "System.Management.Automation.Utils",
            "#$%aBcD^&*Ef",
        ];
    }

    const NORMAL: &[&str] = &[
        "AMSI\\Providers\\",
        "AmsiEnable",
        "AmsiScanBuffer",
        "AmsiUtils",
        "Invoke-Mimikatz",
        "System.Management.Automation.AmsiUtils",
        "System.Management.Automation.Utils",
        "#$%aBcD^&*Ef",
    ];


    #[test]
    fn lowercased() {
        for i in 0..NORMAL.len() {
            assert_eq!(NORMAL[i].to_ascii_lowercase(), LOWERCASED[i].to_string());
        }
    }

    const SHA256_STRINGS: &[&str] = &[
        "cf07194ee232eb531e15f690000d19846dea69cf05504782658afcfacb9228a2",
        "C8DB0D2346289178F9E83689F3BC0947AA17FF609994AC106A85B69CDC321712",
    ];

    compile_sha256_set! {
        const SHA256_HEX: &[&str] = &[
            "cf07194ee232eb531e15f690000d19846dea69cf05504782658afcfacb9228a2",
            "C8DB0D2346289178F9E83689F3BC0947AA17FF609994AC106A85B69CDC321712",
        ];
    }

    #[test]
    fn compile_sha256_set() {
        for i in 0..SHA256_STRINGS.len() {
            assert!(SHA256_HEX.contains(&<[u8; 32]>::from_hex(SHA256_STRINGS[i]).unwrap()));
        }
    }
}