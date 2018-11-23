
package newhope;

/**************************************************************************************************
 *
 * Implements objects for public and private keys including key generation functions for the New
 * Hope algorithms.
 *
 * To improve efficiency, all elements are kept in the Fourier domain and only translated back to
 * compute the shared key at the end. This avoids converting back and forth each time a ring elt
 * multiplication is performed.
 *  
 **************************************************************************************************/

import java.math.BigInteger;
import java.util.Arrays;


class NewHopePublicKey {
  private RingElt key;


  public NewHopePublicKey (NewHopePrivateKey k, RingElt a) {
    RingElt e = Sample.getSample ();
    e.ntt ();
    // Multiply by 3 because of Longa/Naehrig modular reduction optimizations
    e.multByConst (3);                         
    key = a.pointwiseMultAdd (k.getS (), e);
    //key.correction ();
  }


  public NewHopePublicKey (NewHopePrivateKey k, RingElt e, RingElt a) {
    e.ntt ();
    key = a.pointwiseMultAdd (k.getS (), e);
  }


  public NewHopePublicKey (RingElt b) {
    key = new RingElt (b);
  }

  
  public NewHopePublicKey (NewHopePublicKey k) {
    key = new RingElt (k.key);
  }


  public NewHopePublicKey (byte[] inBytes) {
    key = new RingElt (inBytes);
  }


  public RingElt getKey () {
    return key;
  }


  public byte[] serialize () {
    return key.toByteArray();
  }


  public int hashcode () {
    return Arrays.hashCode (serialize());
  }
}


class NewHopePrivateKey {
  private RingElt s;
  private byte domain;

  
  public NewHopePrivateKey (RingElt sIn, byte dom) {
    s = new RingElt (sIn);
    if (dom == Constants.ORDINARY)
      s.ntt();
    domain = Constants.FOURIER;
  }


  public NewHopePrivateKey () {
    s = Sample.getSample ();
    domain = Constants.ORDINARY;
  }


  public NewHopePrivateKey (byte[] inBytes) {
    domain = inBytes[0];
    s = new RingElt (Arrays.copyOfRange (inBytes, 1, inBytes.length));
  }


  public RingElt getS () {
    return s;
  }
  

  public void toFourierDomain () {
    if (domain == Constants.ORDINARY) {
      s.ntt();
      domain = Constants.FOURIER;
    }
  }


  public void fromFourierDomain () {
    if (domain == Constants.FOURIER) {
      s.nttInv();
      domain = Constants.ORDINARY;
    }
  }

  
  public byte[] serialize () {
    byte[] sba = s.toByteArray();
    byte[] ba = new byte[sba.length + 1];
    
    ba[0] = domain;
    System.arraycopy (sba, 0, ba, 1, sba.length);
    
    return ba;
  }
}


class NewHopeKeyPair {
  private NewHopePublicKey pubKey; 
  private final NewHopePrivateKey privKey;


  public NewHopeKeyPair (NewHopePrivateKey prKey, RingElt a) {
    privKey = prKey;
    privKey.toFourierDomain();
    pubKey = new NewHopePublicKey (prKey, a);
  }


  public NewHopeKeyPair (NewHopePrivateKey prKey, RingElt e, RingElt a) {
    privKey = prKey;
    privKey.toFourierDomain();
    pubKey = new NewHopePublicKey (prKey, e, a);
  }

  
  public NewHopeKeyPair (byte[] inKey, RingElt a) {
    privKey = new NewHopePrivateKey (inKey);
    privKey.toFourierDomain();
    pubKey = new NewHopePublicKey (privKey, a);
  }

  
  public NewHopeKeyPair (byte[] inKey, RingElt e, RingElt a) {
    privKey = new NewHopePrivateKey (inKey);
    privKey.toFourierDomain();
    pubKey = new NewHopePublicKey (privKey, e, a);
  }
  

  public NewHopeKeyPair (RingElt a) {
    privKey = new NewHopePrivateKey ();
    privKey.toFourierDomain();
    pubKey = new NewHopePublicKey (privKey, a);
  }


  public NewHopePrivateKey getPrivateKey () {
    return privKey;
  }


  public NewHopePublicKey getPublicKey () {
    return pubKey;
  }


  // Generate a new public key with the same private key but new error term
  public void genNewPubKey (RingElt a) {
    pubKey = new NewHopePublicKey (privKey, a);
  }
}
