// SPDX-License-Identifier: MIT

//! Compiles `proto/avp.proto` into the tonic server and client stubs of the gRPC client profile
//! (SPEC 10.3). Every generated type also derives serde with the camelCase field names of the
//! HTTP/JSON profile, so a gRPC message and its JSON body convert one to the other; an absent
//! message field is left out of the JSON, as an HTTP/JSON client leaves it out.

use std::io;

/// Every message-typed field: absent (`None`) in proto3 means absent in the JSON body.
const MESSAGE_FIELDS: &[&str] = &[
    ".avp.SignedManifest.state",
    ".avp.MemberEntry.wrapped_data_key",
    ".avp.CreateRepoRequest.manifest",
    ".avp.CreateRepoRequest.commit",
    ".avp.PushRequest.commit",
    ".avp.PublishManifestRequest.manifest",
    ".avp.PublishManifestRequest.commit",
    ".avp.HeadsResponse.manifest_tip",
];

fn main() -> io::Result<()> {
    let protoc = protoc_bin_vendored::protoc_bin_path().map_err(io::Error::other)?;
    // SAFETY: build scripts are single-threaded; nothing else reads the environment concurrently.
    unsafe { std::env::set_var("PROTOC", protoc) };
    let mut config = tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .type_attribute(
            ".avp",
            "#[derive(serde::Serialize, serde::Deserialize)] #[serde(rename_all = \"camelCase\", default)]",
        );
    for field in MESSAGE_FIELDS {
        config = config.field_attribute(field, "#[serde(skip_serializing_if = \"Option::is_none\")]");
    }
    config.compile_protos(&["../../../proto/avp.proto"], &["../../../proto"])?;
    println!("cargo:rerun-if-changed=../../../proto/avp.proto");
    Ok(())
}
