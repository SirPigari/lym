# Lym

**Lym** is a package/module manager for [Lucia Programming Language](https://github.com/SirPigari/lucia-rust) made in [Rust](https://rust-lang.org)  
Lym comes preinstalled with Lucia.  

Not to confuse *lym* with <a href="https://en.wikipedia.org/wiki/Lymphoma" style="color:inherit; text-decoration:none;" onmouseover="this.style.textDecoration='underline'" onmouseout="this.style.textDecoration='none'">*lymphoma*</a>

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

- **login** `[--help]`  
  Logs in a user by storing their GitHub username and Personal Access Token.

- **publish** `[package_path] [--help] [--no-confirm] [-v]`  
  Publishes a package to the remote repository. Requires a valid manifest.json and GitHub credentials.

- **new** `[package | module] [name] [path] [--no-confirm] [--help] [--main-file:<name>]`  
  Creates a new package or module at the given path.

## Example

Let's say you want to install the **hello-world** package.  
First you do:

```bash
lym install hello-world
```

And thats all!  
Now you can create a new lucia script and use it freely like this:

```lucia
import (hello_world) from hello_world

print(hello_world())
```

## Adding a Package

1. Create your package, making sure it includes a valid [manifest.json](#manifest) file in the root directory.  
2. Register an account on GitHub and create a [Personal Access Token (PAT)](https://github.com/settings/tokens) and run `lym login` to store your credentials.
3. Run `lym publish <path_to_your_package>` to upload it to the remote repository.
4. Your package is now available for anyone to install using `lym install <package_name>`!

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

- **Test your package before submitting.**  
  Make sure all declared dependencies and config keys work as expected to avoid issues for users.

- **Create a `README.md` (or `.txt`) in the root of your package for documentation.**  
  Use this file to explain usage, special setup, examples, or anything else that doesn't belong in `manifest.json`.

---

Following these helps keep the package ecosystem healthy, compatible, and easier to maintain!

## LICENSE

**Lym** is licensed under the [GNU General Public License v3.0 (GPLv3)](LICENSE).
The same for [Lucia Programming Language](https://github.com/SirPigari/lucia-rust).

Each package submitted to Lym can specify its own license using the optional `"license"` field in the manifest.json file. If no license is specified, GPLv3 applies by default.  
