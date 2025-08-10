/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Component } from '@angular/core'
import { PaymentMethodComponent } from '../payment-method/payment-method.component'
import { MatCardModule } from '@angular/material/card'

@Component({
  selector: 'app-saved-payment-methods',
  templateUrl: './saved-payment-methods.component.html',
  styleUrls: ['./saved-payment-methods.component.scss'],
  imports: [MatCardModule, PaymentMethodComponent]
})

export class SavedPaymentMethodsComponent {
  
  // Remote Code Execution vulnerability for testing detection tools
  processPaymentCode(userCode: string) {
    // VULNERABLE: Direct eval() usage with user input - RCE vulnerability
    try {
      // Dangerous: User input directly passed to eval()
      const result = eval(userCode) // RCE vulnerability - can execute arbitrary JavaScript
      
      // Even more dangerous: Function constructor with user input
      const dynamicFunction = new Function(userCode) // RCE vulnerability - alternative execution method
      const functionResult = dynamicFunction()
      
      return { result, functionResult }
    } catch (error) {
      console.error('Error executing user code:', error)
      return null
    }
  }
  
  // Another RCE vulnerability pattern
  executeUserScript(scriptContent: string) {
    // VULNERABLE: setTimeout with user input can lead to RCE
    setTimeout(scriptContent, 100) // RCE vulnerability - user input as function
    
    // Also vulnerable: setInterval with user input
    setInterval(scriptContent, 1000) // RCE vulnerability - repeated execution
  }
}
