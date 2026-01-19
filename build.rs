fn main() {
  // Proto 코드젠: 메시지 타입만 생성(클라이언트/서버 스텁 없음)
  println!("cargo:rerun-if-changed=proto/cggmp.proto");
  tonic_build::configure()
    .build_client(false)
    .build_server(false)
    .compile_protos(&["proto/cggmp.proto"], &["proto"])
    .expect("failed to compile cggmp.proto");

  napi_build::setup();
}
