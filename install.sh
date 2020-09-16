#!/bin/sh

set -ex

cur_dir=$(cd `dirname "$0"`; pwd)

JNI_LIBS=$cur_dir/e2eesdk/android/jniLibs
#JNI_LIBS=/Users/Bean/rustProjects/android/example/Greetings/app/src/main/jniLibs

cargo build --target aarch64-linux-android --release
cargo build --target armv7-linux-androideabi --release
cargo build --target i686-linux-android --release

rm -rf $JNI_LIBS
mkdir $JNI_LIBS

pwd
ls -al $JNI_LIBS

mkdir $JNI_LIBS/arm64-v8a
mkdir $JNI_LIBS/armeabi-v7a
mkdir $JNI_LIBS/x86

cp target/aarch64-linux-android/release/libe2ee_android.so $JNI_LIBS/arm64-v8a/libe2ee.so
cp target/armv7-linux-androideabi/release/libe2ee_android.so $JNI_LIBS/armeabi-v7a/libe2ee.so
cp target/i686-linux-android/release/libe2ee_android.so $JNI_LIBS/x86/libe2ee.so\

cd capi
cbindgen --cpp-compat -l C -s tag -o e2ee.h
cargo build --target x86_64-pc-windows-msvc --release
cargo build --target x86_64-apple-darwin --release 
RUSTFLAGS="-Z embed-bitcode" cargo +ios-arm64 build --target aarch64-apple-ios --release
cargo build --target x86_64-apple-ios --release

cd ..
cp capi/e2ee.h $cur_dir/e2eesdk/ios/e2ee.h
cp capi/e2ee.h $cur_dir/e2eesdk/mac/e2ee.h
cp capi/e2ee.h $cur_dir/e2eesdk/windows/e2ee.h
cp target/x86_64-pc-windows-msvc/release/e2ee.lib $cur_dir/e2eesdk/ios/e2ee.lib
cp target/x86_64-apple-darwin/release/libe2ee.a $cur_dir/e2eesdk/mac/libe2ee.a
lipo -create target/aarch64-apple-ios/release/libe2ee.a target/x86_64-apple-ios/release/libe2ee.a -output $cur_dir/e2eesdk/ios/libe2ee.a

zip -r e2eesdk_all.zip e2eesdk