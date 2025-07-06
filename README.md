# Lym

**Lym** is a package/module manager for [Lucia Programming Language](https://github.com/SirPigari/lucia-rust) made in [Rust](https://rust-lang.org)
Lym comes preinstalled with [Lucia](https://github.com/SirPigari/lucia-rust).

## Commands

`lym`  
- **install** `[package_name] [--no-confirm] [-v] [--help]`  
  Installs one or more packages. Use `--no-confirm` to skip prompts, `-v` for verbose output, or `--help` for usage info.

- **list** `[--remote | --local | --store] [--no-desc] [--no-ver] [--no-std] [--help]`  
  Shows packages installed locally, remotely, or stored. Optional flags hide descriptions, versions, or standard packages.

- **download** `[package_name] [output_path] [--no-confirm] [-v] [--help]`  
  Downloads a package to a specified folder. Flags allow skipping confirmation or showing more details.

- **remove** `[package_name] [--no-confirm] [-v] [--help]`  
  Deletes a package from your system. Use flags to skip confirmation or get verbose output.

- **disable** `[package_name] [--no-confirm] [-v] [--help]`  
  Temporarily disables a package by moving it to the store without deleting it. Confirmation and verbose options available.

- **enable** `[package_name] [--no-confirm] [-v] [--help]`  
  Re-enables a previously disabled package, with optional confirmation and verbose output.

- **config** `[ lym | lucia | fetch ] [--set <key=value>] [--get <key>] [--help] [--no-confirm]`  
  View or update settings for Lym, Lucia, or refetch the config. `fetch` only updates the config without using any arguments.

- **modify** `[package_name] [--stored] <key> [value1 [value2 ...]] [--no-confirm] [--help]`  
  Edits package manifest or stored data by changing keys and values.

- **new** `[package | module] [name] [path] [--no-confirm] [--help] [--main-file:<name>]`  
  Creates a new package or module at the given path.

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
