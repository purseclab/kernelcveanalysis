# Challenge-2.2.Uni.TA1
This is an adaptation of CVE-2024-25466, A directory traversal vulnerablility in React Native Document picker versions prior 9.1.1. This vulnerability has since been [patched](https://github.com/react-native-documents/document-picker/compare/v9.1.0...v9.1.1):
```diff
@@ -316,7 +316,7 @@ private void copyFileToLocalStorage(Context context, WritableMap map, Uri uri) {
if (fileName == null) {
          fileName = String.valueOf(System.currentTimeMillis());
        }
-       File destFile = new File(dir, fileName);
+       File destFile = safeGetDestination(new File(dir, fileName), dir.getCanonicalPath());
        Uri copyPath = copyFile(context, uri, destFile);
        map.putString(FIELD_FILE_COPY_URI, copyPath.toString());
      } catch (Exception e) {
@@ -326,6 +326,14 @@ private void copyFileToLocalStorage(Context context, WritableMap map, Uri uri) {
      }
    }

+   public File safeGetDestination(File destFile, String expectedDir) throws IllegalArgumentException, IOException {
+     String canonicalPath = destFile.getCanonicalPath();
+     if (!canonicalPath.startsWith(expectedDir)) {
+       throw new IllegalArgumentException("The copied file is attempting to write outside of the target directory.");
+     }
+     return destFile;
+   }
+
    public static Uri copyFile(Context context, Uri uri, File destFile) throws IOException {
      try(InputStream inputStream = context.getContentResolver().openInputStream(uri);
          FileOutputStream outputStream = new FileOutputStream(destFile)) {
```

## Exploiting the vulnerability
Due to the lack of verification that a file presided in the expected directory, We are able to overwrite files that belong innocent.apk. By default, innocent.apk contains two files `flag.txt` and `logging.sh`. This logging script is run anytime a file is selected to log the time of use and a string to logcat. Using CVE-2024-25466, we are able to overwrite `logging.sh` with a carefully named crafted script if it is selected by the user. This crafted shell script can then log the contents of `flag.txt` retrieving the flag. 

The source for our Proof of concept is [here](./app/src/main/) and a [compiled poc](poc.apk) is provided.

This version of the proof of concept allows us to overwrite logging.sh with an ELF binary and execute it. We replace `logging.sh` with [dirtypipe](../cuttlefish_dirtypipe/) to show a privilege escalation. 

## Running Instructions
To test our proof of concept, start a cuttlefish environment and install [innocent.apk](innocent.apk) and [poc.apk](poc.apk) using adb
```bash
adb install innocent.apk
adb install poc.apk
```

Then open open the innocent app and navagate to the "EvilRoot" folder (This should appear under "browse files in other apps" or in the "Open from" tab). Before selecting this file, open another terminal and listen for the reverse shell with 
```bash
nc -lvnp 4444
```
Then select the file that appears in EvilRoot.

This proof of concept will likely not work on your machine as is, instead rebuild the poc to ensure properfunction

## Rebuilding
First, update the [dirtypipe.c](./cuttlefish_dirtypipe/dirtypipe.c) with the ip of the machine running the cuttlefish environment. Then, rebuild [dirtypipe](./cuttlefish_dirtypipe/) using the [compile script](./cuttlefish_dirtypipe/compile.sh) (this requires changing the path to the android ndk in compile.sh and possibly a python virtual environment). 

Place dirtypipe in the apk's [assets](./app/src/main/assets/).

Then, rebuild the apk using android studio. This apk should work as expected.