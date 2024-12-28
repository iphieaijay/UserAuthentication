using Microsoft.AspNetCore.Diagnostics;
using UserAuthentication.Domain.Contracts;

namespace UserAuthentication.Middleware
{
    public class GlobalExceptionHandler : IExceptionHandler
    {
        private ILogger<GlobalExceptionHandler> _logger;
        public GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger)
        {
            _logger = logger;
        }
        public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
        {
            _logger.LogError(exception, exception.Message);
            var response = new ErrorResponse
            {
                Message = exception.Message
            };
            switch(exception)
            {
                case BadHttpRequestException:
                    response.StatusCode = StatusCodes.Status400BadRequest;
                    response.Title = exception.GetType().Name;
                    break;
                
                
                default:
                    response.StatusCode = StatusCodes.Status500InternalServerError;
                    response.Title = exception.GetType().Name;
                    break;

            }
            httpContext.Response.StatusCode = response.StatusCode;
            await httpContext.Response.WriteAsJsonAsync(response,cancellationToken);
            return true;
        }
    }
}
