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
    let visibility = input.vis;
    let expanded = quote! {
        #visibility const #ident: [&'static str; #n] = [#(#lowered),*];
    };

    expanded.into()
}

#[proc_macro]
pub fn compile_sha256_set(input: TokenStream) -> TokenStream {
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

    let mut hashes = Vec::new();
    for expr in expr.elems {
        let lit = match expr {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(s),
                ..
            }) => s,
            _ => panic!("expected string literal"),
        };

        let s = lit.value();
        if s.len() != 64 {
            panic!("SHA256 must be 64 hex characters");
        }

        let mut buf = [0u8; 32];
        hex::decode_to_slice(&s, &mut buf).expect("invalid hex");

        let bytes = buf.iter().map(|b| quote! { #b });

        hashes.push(quote! {
            [#(#bytes),*]
        });
    }

    let visibility = input.vis;
    TokenStream::from(quote! {
        #visibility const #ident: phf::Set<[u8; 32]> = phf_set! {
            #(#hashes),*
        };
    })
}
