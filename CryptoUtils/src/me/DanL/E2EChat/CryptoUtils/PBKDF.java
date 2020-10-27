package me.DanL.E2EChat.CryptoUtils;

import at.gadermaier.argon2.Argon2;
import at.gadermaier.argon2.Argon2Factory;
import at.gadermaier.argon2.model.Argon2Type;

/**
 * This is a Password Based Key Derivation Function wrapper class.
 * 
 * It uses Argon2id from here: https://github.com/andreas1327250/argon2-java (licensed under the MIT license,
 * of which a copy can be found both in the Javadocs of functions using any of the Argon2id implementation, and also below).
 * 
 * A significant portion of the workings of this class are derived from the following implementation of Argon2:
 * https://github.com/andreas1327250/argon2-java
 * 
 *  This implementation is licensed under the following terms (MIT license):
 *  
 *	Permission is hereby granted, free of charge, to any person obtaining a copy
 *	of this software and associated documentation files (the "Software"), to deal
 *	in the Software without restriction, including without limitation the rights
 *	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *	copies of the Software, and to permit persons to whom the Software is
 *	furnished to do so, subject to the following conditions:
 *	
 *	The above copyright notice and this permission notice shall be included in all
 *	copies or substantial portions of the Software.
 *	
 *	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *	SOFTWARE.
 *
 *  Copyright (c) 2017 Andreas Gadermaier
 * 
 * @author daniel
 *
 */
public class PBKDF {
	/**
	 * Derives a key using sensible default values. These are on the paranoid side so are unlikely to change.
	 * 
	 * A significant portion of the workings of this method are derived from the following implementation of Argon2:
	 * https://github.com/andreas1327250/argon2-java
	 * 
	 *  This implementation is licensed under the following terms (MIT license):
	 *  
	 *	Permission is hereby granted, free of charge, to any person obtaining a copy
	 *	of this software and associated documentation files (the "Software"), to deal
	 *	in the Software without restriction, including without limitation the rights
	 *	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	 *	copies of the Software, and to permit persons to whom the Software is
	 *	furnished to do so, subject to the following conditions:
	 *	
	 *	The above copyright notice and this permission notice shall be included in all
	 *	copies or substantial portions of the Software.
	 *	
	 *	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	 *	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	 *	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	 *	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	 *	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	 *	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	 *	SOFTWARE.
	 *
	 *  Copyright (c) 2017 Andreas Gadermaier
	 * @return - A derived key
	 */
	public static byte[] deriveKey(byte[] password, byte[] salt) {
		return deriveKey(32, 32, 128000, 4, password, salt);
	}
	
	
	/**
	 * Derives a key using entirely custom values.
	 * 
	 * A significant portion of the workings of this method are derived from the following implementation of Argon2:
	 * https://github.com/andreas1327250/argon2-java
	 * 
	 *  This implementation is licensed under the following terms (MIT license):
	 *  
	 *	Permission is hereby granted, free of charge, to any person obtaining a copy
	 *	of this software and associated documentation files (the "Software"), to deal
	 *	in the Software without restriction, including without limitation the rights
	 *	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	 *	copies of the Software, and to permit persons to whom the Software is
	 *	furnished to do so, subject to the following conditions:
	 *	
	 *	The above copyright notice and this permission notice shall be included in all
	 *	copies or substantial portions of the Software.
	 *	
	 *	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	 *	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	 *	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	 *	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	 *	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	 *	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	 *	SOFTWARE.
	 *
	 *  Copyright (c) 2017 Andreas Gadermaier
	 * @return - A derived key
	 */
	public static byte[] deriveKey(int length, int cpuCost, int memCost, int parallelFactor, byte[] password, byte[] salt) {
		Argon2 hasher = Argon2Factory.create();
		hasher.setMemoryInKiB(memCost);
		hasher.setIterations(cpuCost);
		hasher.setOutputLength(length);
		hasher.setParallelism(parallelFactor);
		hasher.setType(Argon2Type.Argon2id);
		hasher.setPassword(password);
		hasher.setSalt(salt);
		String rawOutput = hasher.hash();
		return BinaryUtils.hexToBytes(rawOutput);
	}
	
}
