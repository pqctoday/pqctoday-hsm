/*
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 */

#ifndef PKCS11_KEM_H_
#define PKCS11_KEM_H_

typedef struct pkcs11_kem_t pkcs11_kem_t;

#include <crypto/key_exchange.h>

/**
 * Implementation of a Key Encapsulation Mechanism (KEM) using PKCS#11 
 */
struct pkcs11_kem_t {

	/**
	 * Implements key_exchange_t interface
	 */
	key_exchange_t ke;
};

/**
 * Create a pkcs11_kem_t instance for a specific method.
 *
 * @param group		key exchange algorithm
 * @return			pkcs11_kem_t instance, or NULL
 */
pkcs11_kem_t *pkcs11_kem_create(key_exchange_method_t group);

#endif
