# DCCNET Link Layer Emulator

**Author:** Pedro Henrique Madeira de Oliveira Pereira

## Usage

To run the **md5 app** (first grading application), use the following interface:

```
$ python tp1.py <IP>:<PORT> <GAS>
```

For the file transfer app (second grading application), you can start the **passive server** using the interface as showed below:

```
$ python tp1.py -s <PORT> <INPUT> <OUTPUT>
```

The server host is set to be `0.0.0.0`.

To run the **active client** for the file transfer app, use the interface below:

```
$ python tp1.py -c <IP>:<PORT> <INPUT> <OUTPUT>
```
