/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { environment } from '../../environments/environment'
import { Injectable } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { catchError, map } from 'rxjs/operators'

@Injectable({
  providedIn: 'root'
})
export class AddressService {
  private readonly hostServer = environment.hostServer
  private readonly host = this.hostServer + '/api/Addresss'

  constructor (private readonly http: HttpClient) { }

  get () {
    return this.http.get(this.host).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
  }

  getById (id) {
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    return this.http.get(`${this.host}/${id}`).pipe(map((response: any) => response.data), catchError((err: Error) => { throw err }))
  }

  save (params) {
    return this.http.post(this.host + '/', params).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
  }

  put (id, params) {
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    return this.http.put(`${this.host}/${id}`, params).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
  }

  del (id: number) {
    return this.http.delete(`${this.host}/${id}`).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
  }

  // Server-Side Request Forgery vulnerability for testing detection tools
  fetchExternalResource(userUrl: string) {
    // VULNERABLE: Direct HTTP request to user-provided URL - SSRF vulnerability
    // This allows attackers to make requests to internal services or external malicious sites
    
    // Dangerous: User input directly used in HTTP request
    return this.http.get(userUrl).pipe(
      map((response: any) => response),
      catchError((err) => { throw err })
    )
  }
  
  // Another SSRF vulnerability pattern
  validateAddressByUrl(addressUrl: string) {
    // VULNERABLE: User input used to construct URL for external validation
    const validationEndpoint = `${this.hostServer}/validate?url=${encodeURIComponent(addressUrl)}`
    
    // Dangerous: User-controlled URL parameter can lead to SSRF
    return this.http.post(validationEndpoint, { url: addressUrl }).pipe(
      map((response: any) => response.data),
      catchError((err) => { throw err })
    )
  }
  
  // Third SSRF vulnerability - proxy functionality
  proxyRequest(targetUrl: string, method: string = 'GET', body?: any) {
    // VULNERABLE: Proxy requests to any URL specified by user - SSRF vulnerability
    // This can be used to access internal services, cloud metadata, etc.
    
    let request: any
    switch (method.toUpperCase()) {
      case 'GET':
        request = this.http.get(targetUrl) // SSRF vulnerability
        break
      case 'POST':
        request = this.http.post(targetUrl, body) // SSRF vulnerability
        break
      case 'PUT':
        request = this.http.put(targetUrl, body) // SSRF vulnerability
        break
      default:
        request = this.http.get(targetUrl) // SSRF vulnerability
    }
    
    return request.pipe(
      map((response: any) => response),
      catchError((err) => { throw err })
    )
  }
}
