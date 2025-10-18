***ABOUT***
Ramsi (Rust Amsi) - custom amsi Rust implementation

Needs rust 1.88

***Installation***
> regsvr32 ramsi.dll

After installation ramsi starts reporting events. A simple log is written using OuputDebugString (you can see it with DbgView tool) and three files are written to "C:\ramsi" directory:
- {pid}_{tid}_{requestNumber}_contentName.info - "exe_file_name: {}\r\napp_name: {}\r\ncontent_name: {}\r\nsession: {}"
- {pid}_{tid}_{requestNumber}_contentName.dmp - raw script content
- {pid}_{tid}_{requestNumber}_contentName.txt - script content converted from utf16 to String 


***Uninstallation***
> regsvr32 /u ramsi.dll

IMPORTANT: you can't delete/replace ramsi.dll if you opened powershell after registration. The dll is simply injected into Powershell process and needs to be unloaded first