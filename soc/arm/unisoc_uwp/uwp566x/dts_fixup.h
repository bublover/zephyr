/* SoC level DTS fixup file */

#define DT_NUM_IRQ_PRIO_BITS	        DT_ARM_V7M_NVIC_E000E100_ARM_NUM_IRQ_PRIORITY_BITS

#define DT_UART_UWP_NAME		DT_UNISOC_UWP_UART_40038000_LABEL
#define DT_UART_UWP_BASE		DT_UNISOC_UWP_UART_40038000_BASE_ADDRESS
#define DT_UART_UWP_SPEED		DT_UNISOC_UWP_UART_40038000_CURRENT_SPEED
#define DT_UART_UWP_CLOCK		DT_UNISOC_UWP_UART_40038000_CLOCK_FREQUENCY
#define DT_UART_UWP_IRQ			DT_UNISOC_UWP_UART_40038000_IRQ_0
#define DT_UART_UWP_IRQ_PRIO	DT_UNISOC_UWP_UART_40038000_IRQ_0_PRIORITY

#define DT_AON_UART_UWP_NAME	DT_UNISOC_UWP_UART_40838000_LABEL
#define DT_AON_UART_UWP_IRQ		DT_UNISOC_UWP_UART_40838000_IRQ_0
#define	DT_AON_UART_UWP_BASE	DT_UNISOC_UWP_UART_40838000_BASE_ADDRESS
#define DT_AON_UART_UWP_SPEED	DT_UNISOC_UWP_UART_40838000_CURRENT_SPEED
#define DT_AON_UART_UWP_CLOCK	DT_UNISOC_UWP_UART_40838000_CLOCK_FREQUENCY
#define DT_AON_UART_UWP_IRQ_PRIO	DT_UNISOC_UWP_UART_40838000_IRQ_0_SENSE

#define DT_WDT_UWP_DEVICE_NAME	DT_UNISOC_UWP_WATCHDOG_40001000_LABEL
#define DT_WDT_UWP_IRQ			DT_UNISOC_UWP_WATCHDOG_40001000_IRQ_0
#define DT_WDT_UWP_IRQ_PRIO		DT_UNISOC_UWP_WATCHDOG_40001000_IRQ_0_PRIORITY
#define DT_WDT_UWP_BASE			DT_UNISOC_UWP_WATCHDOG_40001000_BASE_ADDRESS

#define DT_UWP_ICTL_0_BASE		DT_UNISOC_UWP_INTC_40000000_BASE_ADDRESS
#define DT_UWP_ICTL_0_IRQ		DT_UNISOC_UWP_INTC_40000000_IRQ_0
#define DT_UWP_ICTL_0_IRQ_PRIO	DT_UNISOC_UWP_INTC_40000000_IRQ_0_PRIORITY
#define DT_UWP_ICTL_1_IRQ		DT_UNISOC_UWP_INTC_40000000_IRQ_1
#define DT_UWP_ICTL_1_IRQ_PRIO	DT_UNISOC_UWP_INTC_40000000_IRQ_1_PRIORITY

#define DT_UWP_ICTL_2_BASE		DT_UNISOC_UWP_INTC_40800000_BASE_ADDRESS
#define DT_UWP_ICTL_2_IRQ		DT_UNISOC_UWP_INTC_40800000_IRQ_0
#define DT_UWP_ICTL_2_IRQ_PRIO	DT_UNISOC_UWP_INTC_40800000_IRQ_0_PRIORITY