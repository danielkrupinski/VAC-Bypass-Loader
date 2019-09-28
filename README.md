# VAC Bypass Loader
Loader for [VAC Bypass](https://github.com/danielkrupinski/VAC-Bypass) written in C.

## Getting started

### Prerequisites
Microsoft Visual Studio 2019 (preferably the latest version), platform toolset v142 and Windows SDK 10.0 are required in order to compile VAC Bypass Loader. If you don't have ones, you can download VS [here](https://visualstudio.microsoft.com/) (Windows SDK is installed during Visual Studio Setup).

### Cloning
The very first step in order to compile VAC Bypass Loader is to clone this repo from GitHub to your local computer. Git is required to step futher, if not installed download it [here](https://git-scm.com). Open git bash / git cmd / cmd and enter following command:
```
git clone https://github.com/danielkrupinski/VAC-Bypass-Loader.git
```
`VAC-Bypass-Loader` folder should have been succesfully created, containing all the source files.

### Compiling from source
When you have equiped a copy of source code, next step is opening **VAC-Bypass-Loader.sln** in Microsoft Visual Studio 2019.

Then change build configuration to `Release | x86` and simply press **Build solution**.

If everything went right you should receive `VAC-Bypass-Loader.exe` binary file.

### Running

1. Close Steam client if running.
1. Run `VAC-Bypass-Loader.exe` as Adminitrator. Steam will be opened automatically.

## License
> Copyright (c) 2019 Daniel Krupiński

This project is licensed under the [MIT License](https://opensource.org/licenses/mit-license.php) - see the [LICENSE](LICENSE) file for details.
