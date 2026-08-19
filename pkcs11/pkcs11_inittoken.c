/* pkcs11_inittoken.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Initialize a PKCS#11 token: set its label and SO PIN, then set the user PIN.
 *
 * The other examples in this directory need a token that is already
 * initialized. SoftHSM has softhsm2-util for that, but many PKCS#11
 * implementations ship no such utility - OP-TEE's PKCS#11 trusted application
 * is one, and its tokens come up uninitialized. This example does the job
 * through the PKCS#11 API itself, so it works against any implementation and
 * needs nothing installed on the target beyond the PKCS#11 library.
 *
 * It is safe to re-run: a fully initialized token is left untouched, and one
 * left half-initialized by an interrupted run is completed rather than wiped.
 *
 * Note this deliberately talks to the PKCS#11 library directly rather than
 * going through wolfSSL. Token initialization is administrative, not
 * cryptographic, so wolfSSL does not wrap C_InitToken/C_InitPIN.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/pkcs11.h>

/* Not declared in wolfssl/wolfcrypt/pkcs11.h - only the flags wolfSSL itself
 * uses are. From PKCS#11 v2.40, CK_TOKEN_INFO flags. */
#ifndef CKF_TOKEN_INITIALIZED
    #define CKF_TOKEN_INITIALIZED 0x00000400UL
#endif
#ifndef CKF_USER_PIN_INITIALIZED
    #define CKF_USER_PIN_INITIALIZED 0x00000008UL
#endif

/* PKCS#11 labels are a fixed-width, space-padded field - not a C string. */
#define LABEL_SZ 32

static int init_token(CK_FUNCTION_LIST* func, CK_SLOT_ID slotId,
                      const char* label, const char* soPin,
                      const char* userPin)
{
    CK_SESSION_HANDLE session = 0;
    CK_TOKEN_INFO     tokenInfo;
    CK_UTF8CHAR       padded[LABEL_SZ];
    CK_RV             rv;
    int               ret = 0;
    size_t            labelSz;

    labelSz = strlen(label);
    if (labelSz > LABEL_SZ) {
        fprintf(stderr, "Label too long: %d bytes maximum\n", LABEL_SZ);
        return 1;
    }

    memset(&tokenInfo, 0, sizeof(tokenInfo));
    rv = func->C_GetTokenInfo(slotId, &tokenInfo);
    if (rv != CKR_OK) {
        fprintf(stderr, "Failed to get token info: 0x%lx\n", (unsigned long)rv);
        return 1;
    }

    /* Initialization is two steps that can be interrupted between: C_InitToken
     * sets the SO PIN and marks the token initialized, and only a later SO
     * login can set the user PIN. Treat the token as done only when both have
     * happened, so a run that died in between can be completed by re-running
     * rather than needing the token wiped. */
    if ((tokenInfo.flags & CKF_TOKEN_INITIALIZED) != 0 &&
        (tokenInfo.flags & CKF_USER_PIN_INITIALIZED) != 0) {
        printf("Token in slot %lu is already initialized - nothing to do\n",
               (unsigned long)slotId);
        return 0;
    }

    if ((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == 0) {
        memset(padded, ' ', sizeof(padded));
        memcpy(padded, label, labelSz);

        /* Sets the SO PIN and the label, and puts the token in a state where
         * the SO can log in to set the user PIN. */
        rv = func->C_InitToken(slotId, (CK_UTF8CHAR_PTR)soPin,
                               (CK_ULONG)strlen(soPin), padded);
        if (rv != CKR_OK) {
            fprintf(stderr, "Failed to initialize token: 0x%lx\n",
                    (unsigned long)rv);
            return 1;
        }
        printf("Initialized token in slot %lu with label \"%s\"\n",
               (unsigned long)slotId, label);
    }
    else {
        /* Resuming: re-running C_InitToken here would destroy every object
         * already on the token, so pick up at the user PIN instead. The SO PIN
         * must match the one the earlier run set. */
        printf("Token in slot %lu is initialized but has no user PIN"
               " - setting it\n", (unsigned long)slotId);
    }

    /* The user PIN can only be set by the SO, over a read/write session. */
    rv = func->C_OpenSession(slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                             NULL, NULL, &session);
    if (rv != CKR_OK) {
        fprintf(stderr, "Failed to open session: 0x%lx\n", (unsigned long)rv);
        return 1;
    }

    rv = func->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                       (CK_ULONG)strlen(soPin));
    if (rv != CKR_OK) {
        fprintf(stderr, "Failed to login as SO: 0x%lx\n", (unsigned long)rv);
        ret = 1;
    }

    if (ret == 0) {
        rv = func->C_InitPIN(session, (CK_UTF8CHAR_PTR)userPin,
                             (CK_ULONG)strlen(userPin));
        if (rv != CKR_OK) {
            fprintf(stderr, "Failed to set user PIN: 0x%lx\n",
                    (unsigned long)rv);
            ret = 1;
        }
        else {
            printf("User PIN set - token is ready for the other examples\n");
        }
    }

    func->C_CloseSession(session);

    return ret;
}

int main(int argc, char* argv[])
{
    void*                 dlib = NULL;
    CK_C_GetFunctionList  getFuncList;
    CK_FUNCTION_LIST*     func = NULL;
    CK_SLOT_ID            slotId;
    CK_RV                 rv;
    int                   ret;
    unsigned long         slotVal;
    char*                 slotEnd;

    if (argc != 6) {
        fprintf(stderr, "Usage: pkcs11_inittoken <libname> <slot> <tokenname>"
                        " <sopin> <userpin>\n");
        return 1;
    }

    /* strtoul rather than atoi: atoi returns 0 for non-numeric input, which
     * would silently initialize slot 0 - the wrong token, destructively. */
    slotEnd = NULL;
    slotVal = strtoul(argv[2], &slotEnd, 10);
    if (slotEnd == argv[2] || *slotEnd != '\0') {
        fprintf(stderr, "Slot must be a number: %s\n", argv[2]);
        return 1;
    }
    slotId = (CK_SLOT_ID)slotVal;

    dlib = dlopen(argv[1], RTLD_NOW);
    if (dlib == NULL) {
        fprintf(stderr, "Failed to open PKCS#11 library: %s\n", dlerror());
        return 2;
    }

    getFuncList = (CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
    if (getFuncList == NULL) {
        fprintf(stderr, "Library has no C_GetFunctionList\n");
        dlclose(dlib);
        return 2;
    }

    rv = getFuncList(&func);
    if (rv != CKR_OK || func == NULL) {
        fprintf(stderr, "Failed to get function list: 0x%lx\n",
                (unsigned long)rv);
        dlclose(dlib);
        return 2;
    }

    rv = func->C_Initialize(NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "Failed to initialize PKCS#11 library: 0x%lx\n",
                (unsigned long)rv);
        dlclose(dlib);
        return 2;
    }

    ret = init_token(func, slotId, argv[3], argv[4], argv[5]);

    func->C_Finalize(NULL);
    dlclose(dlib);

    return ret;
}
