package com.krzem.hash_passwords;



import java.lang.Exception;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;



public final class Password{
	private final SecureRandom RANDF=new SecureRandom();
	private String salt;
	private String hash;



	public Password(){
		this._setup(1024);
	}



	private void _setup(int l){
		byte[] s=new byte[l];
		this.RANDF.nextBytes(s);
		this.salt=Base64.getEncoder().encodeToString(s);
		s=new byte[2048];
		this.RANDF.nextBytes(s);
		this.hash=Base64.getEncoder().encodeToString(s);
		this._hash();
	}



	private void _hash(){
		PBEKeySpec s=null;
		try{
			MessageDigest md5=MessageDigest.getInstance("MD5");
			char[] chl=new String(md5.digest(this.hash.getBytes()),"UTF-8").toCharArray();
			s=new PBEKeySpec(chl,this.salt.getBytes(),65536,512);
			Arrays.fill(chl,Character.MIN_VALUE);
			this.hash=Base64.getEncoder().encodeToString(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512").generateSecret(s).getEncoded());
		}
		catch (Exception e){
			e.printStackTrace();
		}
		finally{
			s.clearPassword();
		}
	}



	public String encode(String msg){
		try{
			byte[] a=msg.replaceAll("\\\\","\\\\\\\\").replaceAll("\n","\\\\n").replaceAll("\t","\\\\t").getBytes();
			byte[] b=this.hash.getBytes();
			byte[] c=this.salt.getBytes();
			MessageDigest md5=MessageDigest.getInstance("MD5");
			byte[] bh=md5.digest(b);
			byte[] ch=md5.digest(c);
			String s=Integer.toString(Math.abs((Math.max(c.length-b.length,1)+ch[b.length%ch.length])*(int)Math.pow(Math.max(b.length-c.length,1)+bh[c.length%bh.length],3)));
			for (int i=0;i<s.length();i++){
				int j=Math.max(Integer.parseInt(String.valueOf(s.charAt(i)))%a.length,1);
				int k=Integer.parseInt(String.valueOf(s.charAt(s.length()-1-i)))*j;
				if (k==0){
					k=b.length%j+j;
				}
				k+=Math.max(Integer.parseInt(String.valueOf(s.charAt((i+1)%s.length()))),2);
				j=(j*k)%a.length;
				a[j]=(byte)((a[j]+k)&0xfff);
			}
			ArrayList<Byte> o=new ArrayList<Byte>();
			for (int i=0;i<a.length;i++){
				if (bh[i%bh.length]<ch[i%ch.length]){
					byte[] e=new byte[1];
					this.RANDF.nextBytes(e);
					o.add(e[0]);
				}
				if ((bh[i%bh.length]^ch[i%ch.length])<((bh[i%bh.length]-ch[i%ch.length])&0xff)){
					byte[] e=new byte[((bh[i%bh.length]-ch[i%ch.length])&0xff)%10];
					this.RANDF.nextBytes(e);
					for (int j=0;j<e.length;j++){
						o.add(e[j]);
					}
				}
				o.add((byte)(((a[i]^bh[i%bh.length])+ch[i%ch.length])^(bh[i%bh.length]+ch[i%ch.length])));
			}
			byte[] t=new byte[o.size()];
			for (int i=0;i<o.size();i++){
				t[i]=(byte)o.get(i);
			}
			return Base64.getEncoder().encodeToString(t);
		}
		catch (Exception e){
			return null;
		}
		finally{
			this._hash();
		}
	}



	public String decode(String msg){
		try{
			byte[] a=Base64.getDecoder().decode(msg);
			byte[] b=this.hash.getBytes();
			byte[] c=this.salt.getBytes();
			MessageDigest md5=MessageDigest.getInstance("MD5");
			byte[] bh=md5.digest(b);
			byte[] ch=md5.digest(c);
			ArrayList<Byte> o=new ArrayList<Byte>();
			int ti=0;
			for (int i=0;i<a.length;i++){
				if (bh[ti%bh.length]<ch[ti%ch.length]){
					i++;
				}
				if ((bh[ti%bh.length]^ch[ti%ch.length])<((bh[ti%bh.length]-ch[ti%ch.length])&0xff)){
					i+=((bh[ti%bh.length]-ch[ti%ch.length])&0xff)%10;
				}
				o.add((byte)(((a[i]^(bh[ti%bh.length]+ch[ti%ch.length]))-ch[ti%ch.length])^bh[ti%bh.length]));
				ti++;
			}
			byte[] t=new byte[o.size()];
			for (int i=0;i<o.size();i++){
				t[i]=(byte)o.get(i);
			}
			String s=Integer.toString(Math.abs((Math.max(c.length-b.length,1)+ch[b.length%ch.length])*(int)Math.pow(Math.max(b.length-c.length,1)+bh[c.length%bh.length],3)));
			for (int i=0;i<s.length();i++){
				int j=Math.max(Integer.parseInt(String.valueOf(s.charAt(i)))%t.length,1);
				int k=Integer.parseInt(String.valueOf(s.charAt(s.length()-1-i)))*j;
				if (k==0){
					k=b.length%j+j;
				}
				k+=Math.max(Integer.parseInt(String.valueOf(s.charAt((i+1)%s.length()))),2);
				j=(j*k)%t.length;
				t[j]=(byte)((t[j]-k)&0xfff);
			}
			return new String(t);
		}
		catch (Exception e){
			return null;
		}
		finally{
			this._hash();
		}
	}
}