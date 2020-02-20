extern crate proc_macro;

use proc_macro::{TokenStream, TokenTree};
use quote::quote;
use syn::Error;
use proc_macro2::Span;

#[proc_macro_attribute]
pub fn sec(args: TokenStream, input: TokenStream) -> TokenStream {
    let mut link_name = String::new();
    for arg in args.into_iter() {
        if let TokenTree::Literal(lit) = arg {
            link_name = lit.to_string();
        } else {
            let err = Error::new(
                Span::call_site(),
                "Error occured parsing attribute args: must be a string, i.e.:\n seq(\"my_function\")"
            ).to_compile_error();
            return TokenStream::from(err);
        }
    }
    link_name.retain(|c| c != '\"');
    
    let mut tts: TokenStream = TokenStream::new();
    let attr = quote! { #[no_mangle] #[link_section = #link_name] };
    let tts_attr = TokenStream::from(attr);
    tts.extend(tts_attr);
    tts.extend(input);
    tts
}
