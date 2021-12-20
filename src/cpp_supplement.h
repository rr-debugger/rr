/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_CPP_SUPPLEMENT_H_
#define RR_CPP_SUPPLEMENT_H_

#if __cplusplus == 201103L

/**
 * Implementation of make_unique for C++11 (from https://herbsutter.com/gotw/_102/).
 */
template<typename T, typename ...Args>
std::unique_ptr<T> make_unique( Args&& ...args )
{
    return std::unique_ptr<T>( new T( std::forward<Args>(args)... ) );
}

#endif /* __cplusplus == 201103L */

#endif
