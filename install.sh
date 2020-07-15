#!/bin/sh

set -ex

cur_dir=$(cd `dirname "$0"`; pwd)

#JNI_LIBS=$cur_dir/app/src/main/jniLibs
JNI_LIBS=/Users/Bean/rustProjects/android/example/Greetings/app/src/main/jniLibs

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
