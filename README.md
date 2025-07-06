# Lym

**Lym** is a package/module manager for [Lucia Programming Language](https://github.com/SirPigari/lucia-rust) made in [Rust](https://rust-lang.org)

## Commands

`lym`  
- `install [package_name] [--no-confirm] [-v] [--help]`  
  Installs the package you want, with options to skip confirmation, get more details, or see help.

- `list [--remote | --local | --store] [--no-desc] [--no-ver] [--no-std] [--help]`  
  Shows you packages that are installed locally, remotely, or in the store. You can hide descriptions, versions, or standard packages if you want.

- `download [package_name] [output_path] [--no-confirm] [-v] [--help]`  
  Downloads a package to a folder you choose, with options to skip confirmation and see more info.

- `remove [package_name] [--no-confirm] [-v] [--help]`  
  Deletes a package from your system. You can skip confirmation or get detailed output if needed.

- `disable [package_name] [--no-confirm] [-v] [--help]`  
  Temporarily turns off a package without deleting it, with options for confirmation and verbose output.

- `enable [package_name] [--no-confirm] [-v] [--help]`  
  Turns a disabled package back on, also with optional confirmation and detailed output.

- `config [ lym | lucia | fetch ] [--set <key=value>] [--get <key>] [--help] [--no-confirm]`  
  Lets you view or change settings for Lym, Lucia, or refetch the Lym config (fetch just fetches doesnt do anything with the argv).

- `modify [package_name] [--stored] <key> [value1 [value2 ...]] [--no-confirm] [--help]`  
  Changes info in a package's manifest or stored data by updating keys and values.

- `new [package | module] [name] [path] [--no-confirm] [--help] [--main-file:<name>]`  
  Creates a new package or module with your chosen name and location, and you can set the main file if you want.

## Adding a Package

1. Create your package, making sure it includes a valid [manifest.json](#manifest) file in the root directory.  
2. Submit a pull request with your package to the repository for review.  
3. Once approved, your package will be added and available for everyone.


## Manifest

Manifest is a manifest.json file in the root directory of the package.

it should have:
```json
{
    "name": "package",
    "version": "0.1.0",
    "required_lucia_version": "^2.0.0",
    "description": "description",
    "license": "MIT",
    "authors": [
        "your name"
    ],
    "config": {
        "use_preprocessor": true,
    },
    "dependencies" {
        "package2": "^3.69.42"
    }
}
```

### Field Descriptions

- **name** (string, required)  
  The package's name.

- **version** (string, required)  
  The package's version in [semver](https://semver.org/) format.

- **required_lucia_version** (string, required)  
  The minimum compatible version of Lucia required to use this package.

- **description** (string, required)  
  A short description of what the package does.

- **license** (string, optional)  
  The license type for the package (e.g., MIT, GPL).

- **authors** (array of strings, optional)  
  List of package authors.

- **config** (object, optional)  
  Keys that must be enabled in the Lucia config for this package to work properly.

- **dependencies** (object, optional)  
  Package dependencies with version requirements, e.g., `"package2": "^3.69.42"`.

## Good Practices

- **Avoid using `#config` inline preprocessor directives inside your package source.**  
  Instead, declare any required config keys in the `config` field of your `manifest.json`. This keeps configuration centralized and cleaner.

- **For include-type packages (not import), always wrap your source code with include guards.**  
  Use `#ifndef #define` and `#endif` around your code, just like in C, to prevent multiple inclusions and redefinition errors.

- **Keep your `manifest.json` clean and accurate.**  
  Only list actual dependencies in the `dependencies` field. Avoid unnecessary or outdated entries.

- **Keep the `description` field in your manifest short, clear, and easy to read.**  
  This helps users quickly understand what your package does without extra fluff.

- **Specify the minimum required Lucia version precisely using semantic versioning.**  
  This helps ensure your package is used only in compatible environments.

- **Use meaningful and concise descriptions.**  
  This makes your package easier to discover and understand by others.

- **Test your package before submitting.**  
  Make sure all declared dependencies and config keys work as expected to avoid issues for users.

- **Create a `README.md` (or `.txt`) in the root of your package for documentation.**  
  Use this file to explain usage, special setup, examples, or anything else that doesn't belong in `manifest.json`.

---

Following these helps keep the package ecosystem healthy, compatible, and easier to maintain! uwu

## LICENSE

**Lym** is licensed under the [GNU General Public License v3.0 (GPLv3)](LICENSE).
The same for [Lucia Programming Language](https://github.com/SirPigari/lucia-rust).

Each package submitted to Lym can specify its own license using the optional `"license"` field in the manifest.json file.
