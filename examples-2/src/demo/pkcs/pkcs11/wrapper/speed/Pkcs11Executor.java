/*
 *
 * Copyright (c) 2019 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package demo.pkcs.pkcs11.wrapper.speed;

import java.util.concurrent.TimeUnit;

import org.xipki.util.BenchmarkExecutor;
import org.xipki.util.concurrent.ConcurrentBag;

import demo.pkcs.pkcs11.wrapper.util.Util;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;

/**
 * Benchmark executor base class.
 *
 * @author Lijun Liao
 */
public abstract class Pkcs11Executor extends BenchmarkExecutor {

  private final ConcurrentBag<ConcurrentSessionBagEntry> sessions =
      new ConcurrentBag<>();

  protected Pkcs11Executor(String description, Token token, char[] pin)
      throws TokenException {
    super(description);

    for (int i = 0; i < 5; i++) {
      Session session = Util.openAuthorizedSession(token, true, pin);
      sessions.add(new ConcurrentSessionBagEntry(session));
    }
  }

  protected ConcurrentSessionBagEntry borrowSession() {
    ConcurrentSessionBagEntry signer = null;
    try {
      signer = sessions.borrow(1000, TimeUnit.MILLISECONDS);
    } catch (InterruptedException ex) { // CHECKSTYLE:SKIP
    }

    if (signer == null) {
      throw new IllegalStateException("no idle session available");
    }

    return signer;
  }

  protected void requiteSession(ConcurrentSessionBagEntry session) {
    sessions.requite(session);
  }

  @Override
  protected Runnable getTestor() throws Exception {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public void close() {
    ConcurrentSessionBagEntry session;
    try {
      session = sessions.borrow(10, TimeUnit.MILLISECONDS);
      session.value().closeSession();
    } catch (InterruptedException | TokenException ex) {
    } finally {
      super.close();
    }
  }

}
