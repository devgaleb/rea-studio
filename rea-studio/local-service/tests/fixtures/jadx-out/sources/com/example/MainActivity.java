package com.example;
import android.app.Activity;
import android.database.Cursor;
public class MainActivity extends Activity {
  public void onCreate() { SyncService.startSync(); queryContacts(); }
  private Cursor queryContacts() { return getContentResolver().query(android.provider.ContactsContract.Contacts.CONTENT_URI, null, null, null, null); }
}
