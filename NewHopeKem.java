
package newhope;

/**************************************************************************************************
 *
 * Implements New Hope Key Encapsulation Mechanism (KEM). 
 *
 * Efforts to prevent timing attacks often result in increased code complexity, but the importance 
 * is sufficient enough to warrant those efforts even if it makes parts of the implementation more 
 * difficult to read or comprehend.
 *
 **************************************************************************************************/

import java.util.Arrays;
import java.math.BigInteger;
import java.util.Random;
import java.security.*;


class NewHopeKem {
  RingElt a;
  byte aDomain;
  byte transmitDomain;

  public NewHopeKem () {
    a = new RingElt (Constants.A);              // Use default value of a if none is supplied
    initialize (a, Constants.ORDINARY, Constants.FOURIER);
  }


  public NewHopeKem (RingElt aIn, byte aDom, byte tDom) {
    initialize (aIn, aDom, tDom);
  }


  private void initialize (RingElt aIn, byte aDom, byte tDom) {
    RingElt.initialize ();
    transmitDomain = tDom;
    a = aIn;
    if (aDom == Constants.ORDINARY)
      a.ntt();
    aDom = Constants.FOURIER;
  }
    
  
  public RingElt getA () {
    return new RingElt (a);
  }


  public NewHopeKeyPair generateKeyPair () {
    return new NewHopeKeyPair (a);
  }


  public NewHopeKeyPair generateKeyPair (byte[] inKey) {
    return new NewHopeKeyPair (inKey, a);  
  }


  public byte[][] encapsulate (NewHopePrivateKey t, NewHopePublicKey b) {
    byte[][] result = new byte[2][];
    RingElt v, vprime, eprime;
    
    Random rand = new Random();
    byte[] k = new byte[32];
    rand.nextBytes (k);

    v = encode (k);

    eprime = Sample.getSample ();
    
    vprime = b.getKey().pointwiseMult (t.getS());
    vprime.nttInv();
    vprime = vprime.ringAdd (eprime);
    
    vprime = vprime.ringAdd (v);
    result[0] = vprime.toByteArray ();

    try {
      
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      result[1] = md.digest (k);

    } catch (NoSuchAlgorithmException e) {

      result[1] = new byte[32];
      System.arraycopy (k, 0, result[1], 0, k.length);

    }
    
    return result;
  }


  private RingElt encode (byte[] k) {
    RingElt v = new RingElt ();
    long mask, value;
    long halfq = Constants.Q / 2;

    for (int i = 0; i < 32; i++)
      for (int j = 0; j < 8; j++) {
	mask = - (long) ((k[i] >> j) & 1);
	value = ((long) mask) & halfq;
	v.setCoeff (8*i + j +   0, value);
	v.setCoeff (8*i + j + 256, value);
	v.setCoeff (8*i + j + 512, value);
	v.setCoeff (8*i + j + 768, value);
      }

    return v;
  }


  public byte[] decapsulate (NewHopePrivateKey s, NewHopePublicKey u, RingElt vprime) {
    byte[] k;
    RingElt tmp = u.getKey().pointwiseMult (s.getS());

    tmp.nttInv ();
    tmp = vprime.ringSub (tmp);

    k = decode (tmp);

    try {
      
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      return md.digest (k);
      
    } catch (NoSuchAlgorithmException e) {

      return k;
      
    }
  }


  private byte[] decode (RingElt vprime) {
    byte[] k = new byte[32];
    long t;
    long halfq = (Constants.Q - 1) / 2;

    for (int i = 0; i < 256; i++) {
      t  = abs(vprime.getCoeff (i +   0) - halfq);
      t += abs(vprime.getCoeff (i + 256) - halfq);
      t += abs(vprime.getCoeff (i + 512) - halfq);
      t += abs(vprime.getCoeff (i + 768) - halfq);
      t = (t - Constants.Q) >>> (Long.SIZE-1);
      
      k[i >> 3] |= (byte) (t << (i & 7));
    }

    return k;
  }


  private long abs (long x) {
    long mask = x >> (Long.SIZE - 1);
    return ((mask ^ x) - mask);
  }


  private void printByteArray (byte[] in) {
    System.out.print ("0x");
    for (int i = 0; i < in.length; i++)
      System.out.printf ("%02x ", in[i]);
  }
}

