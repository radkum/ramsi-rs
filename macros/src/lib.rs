use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemConst, parse_macro_input};

#[proc_macro]
pub fn lowercase_const_array(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemConst);
    let ident = input.ident;
    let expr = match *input.expr {
        syn::Expr::Array(arr) => arr,
        syn::Expr::Reference(ref_expr) => {
            if let syn::Expr::Array(arr) = *ref_expr.expr {
                arr
            } else {
                panic!("Expected array expression");
            }
        },
        _ => panic!("Expected array expression"),
    };

    let lowered: Vec<_> = expr
        .elems
        .iter()
        .map(|elem| {
            if let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(lit_str),
                ..
            }) = elem
            {
                let lower = lit_str.value().to_lowercase();
                quote! { #lower }
            } else {
                panic!("Expected string literal");
            }
        })
        .collect();

    let n = lowered.len();
    let expanded = quote! {
        const #ident: [&'static str; #n] = [#(#lowered),*];
    };

    expanded.into()
}
