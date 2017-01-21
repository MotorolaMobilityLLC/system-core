/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _LIBSPARSE_SPARSE_FILE_H_
#define _LIBSPARSE_SPARSE_FILE_H_

#include <sparse/sparse.h>

struct sparse_file {
	unsigned int block_size;
	int64_t len;
	bool verbose;

	struct backed_block_list *backed_block_list;
	struct output_file *out;
};


#endif /* _LIBSPARSE_SPARSE_FILE_H_ */
