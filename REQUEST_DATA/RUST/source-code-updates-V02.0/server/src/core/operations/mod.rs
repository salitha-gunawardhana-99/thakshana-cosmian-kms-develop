/*
Note: In a Rust project, the mod.rs file serves as the main module file within a directory and often provides a central place to manage and organize the modules contained in that directory. This file is typically used to structure larger projects with multiple files by importing and re-exporting other modules, making the code base more modular, maintainable, and organized.
*/

/*
Note: Declaring Modules with mod:

Each mod <module_name>; line tells Rust to include the file <module_name>.rs (e.g., create.rs, decrypt.rs, etc.) as a module within the current module.

This way, you are defining and importing functionality from separate files that encapsulate specific operations (like create, decrypt, export, etc.), so they can be accessed and organized under a single namespace.
 */

mod certify;
mod create;
mod create_key_pair;
mod decrypt;
mod delete_attribute;
mod destroy;
mod dispatch;
mod encrypt;
mod export;
mod export_utils;
mod get;
mod get_attributes;
mod import;
mod locate;
mod message;
mod rekey;
mod rekey_keypair;
mod revoke;
mod set_attribute;
mod validate;
mod wrapping;

/*
Note: Using pub(crate) use to Re-export Modules:

The pub(crate) use statements make these modules accessible within the same crate but not to outside crates. This encapsulation means that only the parts of your codebase that need access to these modules internally will be able to use them, while they are hidden from external users of the crate.

By using use statements, you’re essentially re-exporting certain functions or symbols (like create::create, destroy::destroy_operation, etc.) from the individual modules into this main module. This makes it easier for other parts of the project to access these functions directly through a single, centralized module, rather than importing each module individually.
 */

pub(crate) use certify::certify;
pub(crate) use create::create;
pub(crate) use create_key_pair::create_key_pair;
pub(crate) use decrypt::decrypt;
pub(crate) use delete_attribute::delete_attribute;
pub(crate) use destroy::{destroy_operation, recursively_destroy_key};
pub(crate) use dispatch::dispatch;
pub(crate) use encrypt::encrypt;
pub(crate) use export::export;
pub(crate) use export_utils::export_get;
pub(crate) use get::get;
pub(crate) use get_attributes::get_attributes;
pub(crate) use import::import;
pub(crate) use locate::locate;
pub(crate) use message::message;
pub(crate) use rekey::rekey;
pub(crate) use rekey_keypair::rekey_keypair;
pub(crate) use revoke::{recursively_revoke_key, revoke_operation};
pub(crate) use set_attribute::set_attribute;
pub(crate) use validate::validate_operation;
pub(crate) use wrapping::unwrap_key;

/*
Note: Why Use a mod.rs File?

Centralized Organization: It provides a single location to import and re-export all related modules, making the structure of the project clearer and navigation easier.

Encapsulation: By re-exporting modules as pub(crate), you control visibility within your crate, improving encapsulation and managing access control.

Modularity: It promotes modularity by organizing related functionality (e.g., certify, encrypt, decrypt) into separate modules, which can simplify development, testing, and maintenance.
 */
