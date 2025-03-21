// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::HashMap;

use proc_macro2::TokenStream;
use quote::quote;
use syn::spanned::Spanned;
use syn::*;

struct ActionArg<'a> {
    name: &'a Ident,
    arg_name: String,
}

struct Action<'a> {
    name: &'a Ident,
    action_name: String,
    action_args: Vec<ActionArg<'a>>,
}

enum FieldType {
    Value,
    Lpm,
    Mask,
    Range,
}

struct FieldInfo<'a> {
    name: &'a Ident,
    field_name: String,
    match_type: FieldType,
}

// For a single key, return the code that converts the set of FieldInfo structs
// into a vector of MatchEntryField structs
fn get_match_to_ir_converters(keys: &[FieldInfo]) -> TokenStream {
    let mut tokens = TokenStream::new();
    for key in keys {
        let kname = &key.field_name;
        let field = key.name;

        let conversion = match key.match_type {
            FieldType::Value => quote! {
                aal::MatchEntryValue::Value(
                aal::ValueTypes::from(self.#field) )
            },
            FieldType::Lpm => quote! {
                aal::MatchEntryValue::Lpm(
                aal::MatchLpm::from(self.#field) )
            },
            FieldType::Mask => quote! {
                aal::MatchEntryValue::Mask(
                aal::MatchMask::from(self.#field))
            },
            FieldType::Range => quote! {
                aal::MatchEntryValue::Range(
                aal::MatchRange::from(self.#field) )
            },
        };

        tokens.extend(quote! {
            fields.push(aal::MatchEntryField {
                name: #kname.to_string(),
                value: #conversion,
            });
        });
    }

    tokens
}

// Build the code that converts an IR representation of a key (as captured by a
// MatchData struct) into the original Struct used by dpd.
//
// Ipv4MatchKey {
//     dst_addr: (&a.field_by_name("dst_addr")?.value).try_into()
//     port: (&a.field_by_name("port")?.value).try_into()
// }
fn get_ir_to_match_converters(
    struct_name: &Ident,
    fields: &[FieldInfo],
) -> TokenStream {
    let mut field_code = TokenStream::new();
    for field in fields {
        // Name in the p4 table
        let name = field.name;
        // Name in the rust Struct
        let field_name = &field.field_name;
        #[rustfmt::skip]
        field_code.extend(quote! {
	    #name: (&a.field_by_name(#field_name)?.value)
		.try_into()
		.map_err(|e| {
			let msg = format!("Failed to convert {}: {e:?}",
			  stringify!(#name));
                      aal::AsicError::Internal(msg.into())
                })?,
        });
    }
    quote! {
        #struct_name {
           #field_code
        }
    }
}

fn get_match_key_values(keys: &[FieldInfo]) -> TokenStream {
    let mut tokens = TokenStream::new();
    for key in keys {
        let field = key.name;
        tokens.extend(quote! {
            fields.insert(stringify!(#field).to_string(), self.#field.to_string());
        });
    }

    tokens
}

// Build the code that converts a set of arguments to a vector of ActionArg
// structs as part of an ActionParse::action_arg_to_ir() operation.
fn get_action_arg_to_ir_converters(args: &[ActionArg]) -> TokenStream {
    let mut arg_code = TokenStream::new();

    for arg in args {
        let aname = &arg.arg_name;
        let fname = &arg.name;
        arg_code.extend(quote! {
            args.push(aal::ActionArg {
                name: #aname.to_string(),
                value: aal::ValueTypes::from(* #fname),
            });
        });
    }

    arg_code
}

// Generate the code for conversion of a single Action in an enum to the
// intermediate representation.
//
// We're building something like:
//     Action::Rewrite {dst_mac} => {
//         action = "rewrite";
//         args.push(ActionArg {
//             name: "dst_mac".to_string(),
//             value: aal::ValueTypes::from(*dst_mac),
//         }
//     },
fn get_action_to_ir_converter(
    enum_name: &Ident,
    action: &Action,
) -> TokenStream {
    let ident = action.name;
    let action_name = &action.action_name;

    // If the enum is data-bearing (i.e., if the Action takes one or more
    // arguments), construct the { a, b, c } needed to capture the contents
    // in appropriately named fields as part of the match.
    let mut arg_tokens = TokenStream::new();
    if !action.action_args.is_empty() {
        let mut t = TokenStream::new();
        for arg in &action.action_args {
            let name = arg.name;
            t.extend(quote! { #name , });
        }
        arg_tokens = quote! { { #t } };
    }
    let match_tokens = quote! {#enum_name::#ident #arg_tokens };
    let d = get_action_arg_to_ir_converters(&action.action_args);
    #[rustfmt::skip]
        quote! {
	    #match_tokens => {
		action = #action_name ;
		#d
	    },
	}
}

// Generate the code for conversion an intermediate representation of an Action
// back into the original Enum::Action{args}.  This will look something like:
//     match a.action.as_str() {
//         "rewrite" => Ok(Action::Rewrite {
//             dst_mac: &a.args[0usize].value
//                 .try_into()
//                 .map_err(|_| aal::AsicError::Internal)?,
//         }),
//         "drop" => Ok(Action::DropPacket),
//     }
fn get_ir_to_action_converter(
    enum_name: &Ident,
    action: &Action,
) -> TokenStream {
    let ident = action.name;
    let action_name = &action.action_name;

    // If the enum is data-bearing (i.e., if the Action takes one or more
    // arguments), construct the { a: <value>, b: <value>} needed to convert
    // the args back into enum fields.
    let mut arg_tokens = TokenStream::new();
    if !action.action_args.is_empty() {
        let mut t = TokenStream::new();
        for arg in &action.action_args {
            let name = arg.name;
            #[rustfmt::skip]
            t.extend(quote! {
	    #name: (&a.arg_by_name(stringify!(#name))?.value)
                .try_into()
                .map_err(|e| {
		    let msg = format!("Failed to convert {}: {e:?}",
			stringify!(#name));
                    aal::AsicError::Internal(msg.into())
                })?,
	    });
        }
        arg_tokens = quote! { { #t } };
    }
    #[rustfmt::skip]
        quote! {
	    #action_name => Ok( #enum_name::#ident #arg_tokens),
	}
}

// Generate the code for getting the name of an action
//
// We're building something like:
//         Action::Rewrite { .. } => "rewrite".to_string(),
//         Action::Drop => "drop".to_string(),
//     },
fn get_action_name_converter(
    enum_name: &Ident,
    action: &Action,
) -> TokenStream {
    let ident = action.name;
    let action_name = &action.action_name;

    // If the enum is data-bearing (i.e., if the Action takes one or more
    // arguments), construct the { a, b, c } needed to capture the contents
    // in appropriately named fields as part of the match.
    let mut match_tokens = quote! {#enum_name::#ident };
    if !action.action_args.is_empty() {
        match_tokens.extend(quote! { {..} });
    }

    #[rustfmt::skip]
    quote! {
	#match_tokens => #action_name.to_string(),
    }
}

// Build the code that walks through the list of arguments to an action,
// converts the value of each argument to a string, and pushes that string onto
// a vector.  Like this:
//
//    match self {
//	    Action::Rewrite { dst_mac } => vec![ dst_mac.to_string() ],
//	    Action::DropPacket => vec![]
//    }
fn get_action_arg_converter(enum_name: &Ident, action: &Action) -> TokenStream {
    let ident = action.name;

    let mut match_tokens = TokenStream::new();
    let mut arg_tokens = TokenStream::new();

    if !action.action_args.is_empty() {
        let mut tmp = TokenStream::new();
        for arg in &action.action_args {
            let fname = arg.name;
            tmp.extend(quote! { #fname , });
            arg_tokens.extend(quote! {
                args.insert(stringify!(#fname).to_string(), #fname.to_string());
            });
        }
        match_tokens = quote! { { #tmp } };
    }
    let match_tokens = quote! {#enum_name::#ident #match_tokens };

    quote! { #match_tokens => { #arg_tokens }, }
}

// Parse a single a = b attribute into an (a, b) tuple
fn get_attribute(m: &Meta) -> Result<(String, String)> {
    let err = Error::new(m.span(), "malformed attribute".to_string());
    let nv = match m {
        Meta::NameValue(nv) => nv,
        _ => return Err(err),
    };
    let attr = match nv.path.segments.first() {
        Some(seg) => seg.ident.to_string(),
        None => return Err(err),
    };
    let val = match &nv.lit {
        Lit::Str(l) => l.value(),
        _ => return Err(err),
    };

    Ok((attr, val))
}

fn is_matching_attribute(a: &Attribute, family: &str) -> bool {
    if let Some(ps) = a.path.segments.first() {
        ps.ident == family
    } else {
        false
    }
}

// From a #[action_xlate(..)] or #[match_xlate(..)] directive, extract all of
// the 'attribute = "value"' pairs
fn get_attributes(
    span: proc_macro2::Span,
    family: &str,
    attrs: &[Attribute],
) -> Result<HashMap<String, String>> {
    let mut found = HashMap::new();

    let err = Error::new(span, "bad attribute list".to_string());
    for a in attrs {
        if is_matching_attribute(a, family) {
            let list = match a.parse_meta() {
                Ok(Meta::List(l)) => l,
                _ => return Err(err),
            };
            for i in list.nested.iter() {
                let m = match i {
                    NestedMeta::Meta(m) => m,
                    _ => return Err(err),
                };
                let (attr, val) = get_attribute(m)?;
                found.insert(attr, val);
            }
        }
    }
    Ok(found)
}

// Given a struct, return a vector representing each element of the struct as a
// FieldInfo
fn get_fields<'a>(
    data: &'a Data,
    attr_name: &'static str,
) -> Result<Vec<FieldInfo<'a>>> {
    let mut fields = Vec::new();

    let named = {
        match *data {
            Data::Struct(ref data) => match data.fields {
                Fields::Named(ref f) => &f.named,
                _ => return Ok(fields),
            },
            _ => return Ok(fields),
        }
    };

    for f in named.iter() {
        let name = f.ident.as_ref().unwrap();
        let attrs = get_attributes(f.span(), attr_name, &f.attrs)?;

        let match_type = match attrs.get("type") {
            None => FieldType::Value,
            Some(t) => match t.as_str() {
                "value" => FieldType::Value,
                "lpm" => FieldType::Lpm,
                "mask" => FieldType::Mask,
                "range" => FieldType::Range,
                x => {
                    return Err(Error::new(
                        f.span(),
                        format!("unrecognized key type: {x}"),
                    ))
                }
            },
        };

        let field_name = match attrs.get("name") {
            Some(x) => x.clone(),
            None => name.to_string(),
        };

        fields.push(FieldInfo {
            name,
            field_name,
            match_type,
        });
    }

    Ok(fields)
}

// Parse all of the arguments to an action
fn get_action_args(variant: &Variant) -> Result<Vec<ActionArg>> {
    let mut args = Vec::new();

    let named = match variant.fields {
        Fields::Named(ref f) => &f.named,
        _ => return Ok(args),
    };

    for arg in named.iter() {
        let name = arg.ident.as_ref().unwrap();

        // If we want to allow the caller to override the default name for
        // this argument, we will need a new attribute.
        let arg_name = arg.ident.as_ref().unwrap().to_string();

        args.push(ActionArg { name, arg_name });
    }

    Ok(args)
}

// Given an enum, return a Vec with all of the possible actions and their
// arguments.
fn get_actions<'a>(
    data: &'a Data,
    attr_name: &'static str,
) -> Result<Vec<Action<'a>>> {
    let enum_variants = {
        match *data {
            Data::Enum(ref e) => &e.variants,
            _ => panic!("no actions defined"),
        }
    };

    let mut actions = Vec::new();
    for v in enum_variants.iter() {
        let name = &v.ident;

        let attrs = get_attributes(v.span(), attr_name, &v.attrs)?;
        let action_name = match attrs.get("name") {
            Some(x) => x.clone(),
            None => name.to_string(),
        };

        let action_args = get_action_args(v)?;
        actions.push(Action {
            name,
            action_name,
            action_args,
        });
    }

    Ok(actions)
}

// For a single struct, derive the code needed to implement the MatchParse trait
// for it.
#[proc_macro_derive(MatchParse, attributes(match_xlate))]
pub fn derive_match_xlate(
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = input.ident;

    let f = match get_fields(&input.data, "match_xlate") {
        Ok(f) => f,
        Err(e) => return e.to_compile_error().into(),
    };

    let to_ir_all = get_match_to_ir_converters(&f);
    let from_ir_all = get_ir_to_match_converters(&name, &f);
    let match_key_values = get_match_key_values(&f);

    #[rustfmt::skip]
    let post = quote! {
        impl MatchParse for #name {
            fn key_values(&self) -> std::collections::BTreeMap<String, String> {
		let mut fields = std::collections::BTreeMap::new();
		#match_key_values

		fields
	    }

            fn key_to_ir(&self) -> aal::AsicResult<aal::MatchData> {
		let mut fields = Vec::new();
		#to_ir_all
		Ok(aal::MatchData { fields })
	    }

            fn ir_to_key(a: &aal::MatchData) -> aal::AsicResult<Self> {
		Ok( #from_ir_all )
	    }
	}
    };

    proc_macro::TokenStream::from(post)
}

// For an enum of actions, derive the code needed to implement the ActionParse
// trait for it.
#[proc_macro_derive(ActionParse, attributes(action_xlate))]
pub fn derive_action_xlate(
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let enum_name = input.ident;

    // Parse the ActionParse enum to identify each action and its args
    let actions = match get_actions(&input.data, "action_xlate") {
        Ok(a) => a,
        Err(e) => return e.to_compile_error().into(),
    };

    // Iterate over all the possible actions for this table (as represented by
    // an ActionParse enum) and build the "match" code that converts an action
    // to the intermediate representation, that converts it back to an enum,
    // that returns the name of the action, and which returns the arguments to
    // an action as a vector of strings.
    let mut to_ir_all = TokenStream::new();
    let mut from_ir_all = TokenStream::new();
    let mut action_name = TokenStream::new();
    let mut action_args = TokenStream::new();
    for a in &actions {
        to_ir_all.extend(get_action_to_ir_converter(&enum_name, a));
        from_ir_all.extend(get_ir_to_action_converter(&enum_name, a));
        action_name.extend(get_action_name_converter(&enum_name, a));
        action_args.extend(get_action_arg_converter(&enum_name, a));
    }

    #[rustfmt::skip]
    let post = quote! {
	impl ActionParse for #enum_name {
	    fn action_name(&self) -> String {
		match self {
		    #action_name
		}
	    }

	    fn action_args(&self) -> std::collections::BTreeMap<String, String> {
		let mut args = std::collections::BTreeMap::new();
		match self {
		    #action_args
		}

		args
	    }

            fn action_to_ir(&self) -> aal::AsicResult<aal::ActionData> {
 	    	let action;
		let mut args = Vec::new();
		match self {
		    #to_ir_all
		};
		Ok( aal::ActionData { action: action.to_string(), args })
	    }

            fn ir_to_action(a: &aal::ActionData) -> aal::AsicResult<Self> {
		match a.action.as_str() {
		    #from_ir_all
		    x => Err(aal::AsicError::Internal(
			format!("found unknown action: {x}"))),
		}
	    }
	}
    };

    proc_macro::TokenStream::from(post)
}
