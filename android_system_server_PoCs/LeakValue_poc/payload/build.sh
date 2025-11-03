#!/bin/sh

rm -rf out_classes out_dex runner.jar classes.jar
javac --release 8 -d out_classes xyz/cygnusx/runner/RunnerMain.java 2>/dev/null
jar -cf classes.jar -C out_classes . 
mkdir out_dex                                                  
# ~/Library/Android/sdk/build-tools/34.0.0/d8 --output out_dex classes.jar # replace with location of d8
d8 --output out_dex classes.jar # replace with location of d8
cd out_dex                                                     
jar -cf ../runner.jar classes.dex
cd ..
# echo "echo \"$(base64 -i runner.jar)\" | base64 -d > runner.jar; dalvikvm -cp ./runner.jar xyz.cygnusx.runner.RunnerMain 2>&1"
