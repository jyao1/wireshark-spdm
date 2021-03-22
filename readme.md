# This spdm plug in for wireshark
1) Quick Setup Wireshark Development Environment
   Refer to https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html.
   
   > set WIRESHARK_PATH = C:\Development\wireshark
   
2) Setup spdm plug in development environment
   > git clone https://github.com/jyao1/wireshark-spdm.git
   
   Copy spdm folder to %WIRESHARK_PATH%\plugins\epan.
   
   > git clone https://github.com/jyao1/openspdm.git
   
   Copy openspdm folder to %WIRESHARK_PATH%.
   
3) Build dependent library
   > cd %WIRESHARK_PATH%\openspdm
   > mkdir build
   > cd build
   > cmake -G"NMake Makefiles" -DARCH=X64 -DTOOLCHAIN=VS2019 -DTARGET=Debug -DCRYPTO=<MbedTls|Openssl> -DTESTTYPE=WireShark ..
   
4) Build Wireshark and plugin
   Refer to chapter 2.2.13 of https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html.
   
   
   