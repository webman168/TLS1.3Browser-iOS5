#import "TLS13AppDelegate.h"
#import "TLS13URLProtocol.h"

// Conform to UITextFieldDelegate to monitor keyboard execution flags
@interface TLS13AppDelegate () <UIWebViewDelegate, UITextFieldDelegate>
@end

@implementation TLS13AppDelegate {
    UITextField *_urlAddressBar;
    UIWebView *_webView;
    UITextView *_consoleLog;
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    [NSURLProtocol registerClass:[TLS13URLProtocol class]];
    
    // Listen for global notifications sent from our network protocol file
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(handleLogNotification:) name:@"TLS13LogNotification" object:nil];
    
    CGRect screenBounds = [[UIScreen mainScreen] bounds];
    self.window = [[UIWindow alloc] initWithFrame:screenBounds];
    UIViewController *rootViewController = [[UIViewController alloc] init];
    
    CGFloat topOffset = 0.0;
    
    // Handle status bar geometry offsets if present on early iOS versions
    if (![[UIApplication sharedApplication] isStatusBarHidden]) {
        CGRect statusBarFrame = [[UIApplication sharedApplication] statusBarFrame];
        topOffset = statusBarFrame.size.height;
    }
    
    CGFloat usableHeight = screenBounds.size.height - topOffset;
    CGFloat addressBarHeight = 40.0;
    
    // Console log split: Exactly 20% of the usable screen real estate
    CGFloat consoleHeight = usableHeight * 0.20;
    CGFloat webViewHeight = usableHeight - addressBarHeight - consoleHeight;
    
    // 1. Setup URL Address Bar Frame
    CGRect urlFrame = CGRectMake(0, topOffset, screenBounds.size.width, addressBarHeight);
    _urlAddressBar = [[UITextField alloc] initWithFrame:urlFrame];
    _urlAddressBar.borderStyle = UITextBorderStyleRoundedRect;
    _urlAddressBar.font = [UIFont systemFontOfSize:14.0];
    _urlAddressBar.autocorrectionType = UITextAutocorrectionTypeNo;
    _urlAddressBar.autocapitalizationType = UITextAutocapitalizationTypeNone;
    _urlAddressBar.keyboardType = UIKeyboardTypeURL;
    _urlAddressBar.returnKeyType = UIReturnKeyGo; // Transform keyboard button to 'Go'
    _urlAddressBar.clearButtonMode = UITextFieldViewModeWhileEditing;
    _urlAddressBar.contentVerticalAlignment = UIControlContentVerticalAlignmentCenter;
    _urlAddressBar.placeholder = @"Enter secure URL (e.g., https://...)";
    _urlAddressBar.text = @"https://www.wikipedia.org/";
    _urlAddressBar.delegate = self;
    [rootViewController.view addSubview:_urlAddressBar];
    
    // 2. Setup Web View Frame (Positioned directly under address bar)
    CGRect webFrame = CGRectMake(0, topOffset + addressBarHeight, screenBounds.size.width, webViewHeight);
    _webView = [[UIWebView alloc] initWithFrame:webFrame];
    _webView.scalesPageToFit = YES;
    _webView.delegate = self;
    [rootViewController.view addSubview:_webView];
    
    // 3. Setup Shrunk Live Text Console Log Frame (Flush at the bottom)
    CGRect consoleFrame = CGRectMake(0, topOffset + addressBarHeight + webViewHeight, screenBounds.size.width, consoleHeight);
    _consoleLog = [[UITextView alloc] initWithFrame:consoleFrame];
    _consoleLog.backgroundColor = [UIColor blackColor];
    _consoleLog.textColor = [UIColor greenColor];
    _consoleLog.font = [UIFont fontWithName:@"Courier" size:10.0]; // Slightly smaller font to fit layout
    _consoleLog.editable = NO;
    _consoleLog.text = @"--- TLS 1.3 Browser Console Initialized ---\n";
    [rootViewController.view addSubview:_consoleLog];
    
    self.window.rootViewController = rootViewController;
    [self.window makeKeyAndVisible];
    
    // Load default homepage route
    [self loadUrlFromString:_urlAddressBar.text];
    
    return YES;
}

- (void)loadUrlFromString:(NSString *)urlString {
    NSString *sanitizedString = [urlString stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    
    if (sanitizedString.length == 0) return;
    
    // Automatically prepend https:// protocol wrapper if the user leaves it off
    if (![sanitizedString hasPrefix:@"http://"] && ![sanitizedString hasPrefix:@"https://"]) {
        sanitizedString = [NSString stringWithFormat:@"https://%@", sanitizedString];
        _urlAddressBar.text = sanitizedString;
    }
    
    [self logToConsole:[NSString stringWithFormat:@"Navigating context to: %@", sanitizedString]];
    NSURL *targetURL = [NSURL URLWithString:sanitizedString];
    NSURLRequest *request = [NSURLRequest requestWithURL:targetURL];
    [_webView loadRequest:request];
}

#pragma mark - UITextFieldDelegate (Keyboard Handling)
- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    // Dismiss keyboard tray safely from the window layer
    [textField resignFirstResponder];
    
    // Fire off network protocol request loop
    [self loadUrlFromString:textField.text];
    return YES;
}

- (void)logToConsole:(NSString *)message {
    dispatch_async(dispatch_get_main_queue(), ^{
        _consoleLog.text = [_consoleLog.text stringByAppendingFormat:@"%@\n", message];
        if (_consoleLog.text.length > 0) {
            [_consoleLog scrollRangeToVisible:NSMakeRange(_consoleLog.text.length - 1, 1)];
        }
    });
}

- (void)handleLogNotification:(NSNotification *)notification {
    [self logToConsole:notification.object];
}

#pragma mark - UIWebViewDelegate
- (void)webViewDidStartLoad:(UIWebView *)webView {
    [[UIApplication sharedApplication] setNetworkActivityIndicatorVisible:YES];
    [self logToConsole:@"UIWebView started a loading cycle..."];
    
    // Update the address bar text dynamically if navigating internal site paths
    NSString *currentURL = webView.request.URL.absoluteString;
    if (currentURL.length > 0 && ![currentURL isEqualToString:@"about:blank"]) {
        _urlAddressBar.text = currentURL;
    }
}

- (void)webViewDidFinishLoad:(UIWebView *)webView {
    [[UIApplication sharedApplication] setNetworkActivityIndicatorVisible:NO];
    [self logToConsole:@"UIWebView finished loading successfully!"];
    
    // Final check to catch trailing redirects in the text block
    NSString *currentURL = webView.request.URL.absoluteString;
    if (currentURL.length > 0 && ![currentURL isEqualToString:@"about:blank"]) {
        _urlAddressBar.text = currentURL;
    }
}

- (void)webView:(UIWebView *)webView didFailLoadWithError:(NSError *)error {
    [[UIApplication sharedApplication] setNetworkActivityIndicatorVisible:NO];
    [self logToConsole:[NSString stringWithFormat:@"UIWebView Error: %@", [error localizedDescription]]];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [_urlAddressBar release];
    [_webView release];
    [_consoleLog release];
    [super dealloc];
}
@end
