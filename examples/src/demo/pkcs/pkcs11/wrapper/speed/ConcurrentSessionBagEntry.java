package demo.pkcs.pkcs11.wrapper.speed;

import org.xipki.util.concurrent.ConcurrentBagEntry;

import iaik.pkcs.pkcs11.Session;

public class ConcurrentSessionBagEntry extends ConcurrentBagEntry<Session> {

  public ConcurrentSessionBagEntry(Session value) {
    super(value);
  }

}
