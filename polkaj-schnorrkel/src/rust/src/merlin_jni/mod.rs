use robusta_jni::bridge;

pub use self::jni::TranscriptData;

#[bridge]
pub mod jni {
  use robusta_jni::convert::{
    Field, Signature, TryFromJavaValue,
  };
  use robusta_jni::jni::objects::AutoLocal;

  #[derive(Signature, TryFromJavaValue)]
  #[package(io.emeraldpay.polkaj.merlin)]
  pub struct TranscriptData<'env: 'borrow, 'borrow> {
      #[allow(dead_code)]
      #[instance]
      raw: AutoLocal<'env, 'borrow>,

      // HACK:
      //  Figure out how to make this simply a `Box<[u8]>` instead of a `Vec<Box<[u8]>>`.
      //  Currently, this is a blocker with byte[] fields; seems to be an issue with robusta itself, perhaps some missing impls...
      //  see: https://github.com/giovanniberti/robusta/issues/69
      #[field]
      pub domainSeparationLabel: Field<'env, 'borrow, Vec<Box<[u8]>>>,

      #[field]
      pub labels: Field<'env, 'borrow, Vec<Box<[u8]>>>,

      #[field]
      pub messages: Field<'env, 'borrow, Vec<Box<[u8]>>>,
  }
}


impl <'env, 'borrow> From<TranscriptData<'env, 'borrow>> for merlin::Transcript {
  // SAFETY:
  //  Since merlin's API requires labels to have a static lifetime, a `Box::leak` invocation is necessary.
  //  This is safe enough, however, since the boxed values are managed by the Java runtime and will be GC'd there when needed,
  //  so Rust doesn't have to worry about that (although it wants to).
  fn from(value: TranscriptData) -> Self {
    // SAFETY: We're purposefully dropping mutability since we want to read only
    let domain_separation_label: &[u8] = Box::leak(
      value.domainSeparationLabel.get().unwrap()
      .first()
      .cloned()
      .unwrap()
    );

    let mut transcript = merlin::Transcript::new(domain_separation_label);

    let message_labels = value.labels.get().unwrap();
    let messages = value.messages.get().unwrap();

    for (label, message) in message_labels.iter().cloned().zip(messages.iter().cloned()) {
      transcript.append_message(Box::leak(label), message.as_ref())
    }

    transcript
  }
}