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
Due to the lack of verification that a file presided in the expected directory, We are able to overwrite files that belong innocent.apk. By default, innocent.apk contains two files `flag.txt` and `logging.sh`. This logging script is run anytime a file is selected to log the time of use and a string to logcat. Using CVE-2024-25466, we are able to overwrite `logging.sh` with a crafted script if it is selected by the user. This crafted shell script can then log the contents of `flag.txt` retrieving the flag. 

The source for our Proof of concept is [here](./app/src/main/) and a [compiled poc](poc.apk) is provided.