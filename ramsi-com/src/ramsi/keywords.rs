use macros::{compile_sha256_set, lowercase_const_array};
use phf::phf_set;

lowercase_const_array! {
pub(super) const BLACKLIST_KEYWORDS: &[&str] = [
    "amsi.dll",
    "amsiInitFailed",
    "AMSI/Providers",
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
    "0F64D161C6DCAEDDA753C20C507F402BD9B076AB3838639EE72ACA53AC8F0A51",
    "2559E968F2DEF70BB14C7152FA07E39B2A97BFDE2C139F4635B6466056F274D6",
    "2F4194E089703E4ED2AFEEC26D7FF20707DE3FABABD3A2E07D243A8331A3A6B6",
    "40DB3944E36269B770A25170276AA23F546186CE55F973639E573662E09A20F6",
    "504D69383B0BAE9818E173EC85D2ACD10A0259AE3F90199C4A5621E4E3BC59EB",
    "5B9A7DD96DF9B3CF87820E6266F34D6EF23FE7D953B066393B8514719719326B",
    "5DAF81002DE2DF4CF93EFAC4955BA32C71A793EB9E52D031B21A9BBBCB8F5D74",
    "5F643286EEF7EFAECA7F6BE7DF26A45CF6E2583BFEC158D701F1FDF0F704E6B0",
    "705AB32DA3787365A113E6BDDDEF88694649AC783923A32373C45532F29E1A65",
    "70AE52B3572E40A6F25D0293C02120C1D100CA970EC15CD3AF4FA6B37779D9C8",
    "77F475086729F640A48A621DEBA6DC1C2A88D347967E7F461A77D58ADC1A5B6E",
    "8773DE3A11FFD84558D1010E9180DBC08E3527861A045BE8F69179500910640B",
    "8B2023173FDF8F44034F09E2E2919979E053D28439934D15B4FFF9122A362EDF",
    "9628C2691947D25ABCDE9EB7DB875915DE5A50F4394F90D1A9CC4788CB4DD95E",
    "97EF98BD21735CF3FA2C7B9C906228D8D1D98CF1962C12195F5BF2C27F7AFC20",
    "98C2733E43FFE148378F645B5626E585578FCFD04FCC2FCB443BA61D54430912",
    "C73738E43D60ECF6F1D7F10A868B1D37999ECAB9623FF6F4C3D19E1B28B5A3BE",
    "CF07194EE232EB531E15F690000D19846DEA69CF05504782658AFCFACB9228A2",
    "D341EDD2C730FE4CE09F59DB8166E4BFC44E913850D232E5602A033826699195",
    "DEB7B1B6779A45F6E6E0E1175F8A837F11D4E45A0D09288B902CCB8B9ACDE305",
    "E67441963B163B8FBC8F93E6CAB0055B7036C63E28AAAF6DF334E302B578D87B",
    "F1BA7C25D531CDC1A9C4A65A7EF3B65777360E993FE3876012AF9E9E97A3D260",
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
