allow :: RadixIPLookup(127.0.0.1 0);
deny :: RadixIPLookup(0.0.0.0/0	0); 
allow -> deny -> allow;

FromDevice(ath0)->RadiotapDecap()->StaTest()->Socket(TCP, 0.0.0.0, 8007, ALLOW allow, DENY deny);
