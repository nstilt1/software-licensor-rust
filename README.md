The code here is unrefined. It uses JUCE's RSA for license activation, but there are some files named "private.rs" missing. The private files contained RSA private keys that are no longer in use, as well as a salt email function.

It's a good thing I refactored the code. I essentially started from scratch again, but with the help of a shared utils crate and Chat GPT.