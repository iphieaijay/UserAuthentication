namespace UserAuthentication.Domain.Contracts
{
    public record CustomResponse(int responseCode, string message, object? data=null);
}
