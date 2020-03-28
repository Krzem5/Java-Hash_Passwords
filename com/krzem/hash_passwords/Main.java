package com.krzem.hash_passwords;



public class Main{
	public static void main(String[] args){
		new Main();
	}



	public Main(){
		Password p=new Password();
		String enc=p.encode("Hi!");
		String enc2=p.encode("Hi!");
		System.out.println(enc);
		System.out.println("\n\n\n"+enc2);
		// System.out.println(Password.decode(enc,hash,salt));
		// System.out.println(Password.decode(enc,hash,salt));
	}
}