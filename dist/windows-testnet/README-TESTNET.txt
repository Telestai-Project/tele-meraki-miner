Telestai Core 3.0.0 TestNet miner (Windows, NVIDIA CUDA)

This zip is only the miner. You do not need Telestai Core, a wallet, or telestai.conf.

1. Install a current NVIDIA Game Ready or Studio driver.
2. If Windows asks for VC++ runtime, install "Microsoft Visual C++ Redistributable (x64)".
3. Unzip this folder and open a Command Prompt in it.
4. Ask Chief for the TestNet mining URL, then run:

     telemerakiminer.exe -U -P http://USER:PASS@HOST:18768/

   Or copy mine-testnet.bat.example to mine-testnet.bat, put the URL on the -P line, and double-click it.

You want to see "Accepted" in the miner window. That is TestNet only — not mainnet TLS.

Do not follow the old 1.5.0 GitHub notes (AppData\Roaming\Telestai, addnode=45.79.159.32, rpcport=8766). Those are for a local 2.1.x wallet, not Core 3.0.0 TestNet.
