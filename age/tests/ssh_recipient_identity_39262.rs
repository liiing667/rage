#![cfg(feature = "ssh")]

use age::ssh::Recipient;

const RSA: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDE7nIXTGNuaRBN9toI/wNALuQec8mvlt0iJ7o3OaD2UvoKHJ7S8rmIn4FiQDUed/Vac3OhUibei1k+TBmm16u2Rj3klgWZOIDgi8d4vXKI5N3YBhxr3jsQ+kz1c+iZ4z/tTtz306+4K46XViVMWwyyg9j82Jn41mOAy9vdeDIfQ5fLeaGqn5KwlT61GNkZ+ozWK/ZNlQIlNCcoXxhJULIs9XrtczWyVBAea1nlDo0WHODePxoJjmsNHrpQXn5mf9O83xs10qfTUjnRUt48jRmedFy4tcra3QGmSTQ3KZne+wXXSb0cIpXLGvZjQSPHgG1hc4r3uBpiSzvesGLv79XL alice@rust";
const ED: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN alice@rust";

#[test]
fn commented_and_control_spelled_lines_share_canonical_identity() {
    for line in [RSA, ED] {
        let trusted: Recipient = line.parse().unwrap();
        let canonical = trusted.to_string();
        let variants = [
            format!("{canonical} reviewer@example"),
            format!("{canonical}\treviewer@example"),
            format!("{canonical} x\u{0000}y\u{0007}\u{001b}[31m"),
            format!("{canonical}\u{001b}[0m\r\n"),
        ];

        for variant in variants {
            let parsed: Recipient = variant.parse().unwrap();
            assert_eq!(parsed, trusted);
            assert_eq!(parsed.canonical_key_blob(), trusted.canonical_key_blob());
            assert_eq!(parsed.sha256_fingerprint(), trusted.sha256_fingerprint());
            assert_eq!(parsed.to_string(), canonical);
        }
    }
}

#[test]
fn fingerprints_match_openssh() {
    let ed: Recipient = ED.parse().unwrap();
    let rsa: Recipient = RSA.parse().unwrap();
    assert_eq!(
        ed.sha256_fingerprint_string(),
        "SHA256:PYX4o9UfGwCwG76hFcLAEkmMS0PtIBtV9MNmVgW16Oc"
    );
    assert_eq!(
        rsa.sha256_fingerprint_string(),
        "SHA256:jH4CHm2hFu7eduLrU2NqOn1Uk1zva6DohXCLFfCw734"
    );
}
