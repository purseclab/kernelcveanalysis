# Fuzzing

Proceed after ssh-ing to tofu with sungwoo's account.  
I recommend opening multiple terminals.

1. start cvd (~2mins)
```
tmux attach -t 0
cd
./run.sh
```

2. (optional) see kernel log
```
./log.sh
```

3. run Syzkaller 
```
./fuzz.sh
```

4. In your machine, forward a port to see Syzkaller's dashboard
```
ssh -L 56741:localhost:56741 sungwoo
```

5. Open `http://localhost:56741` and see the fuzzing progress.

⚠️ coverage collection may take 2 mins.
