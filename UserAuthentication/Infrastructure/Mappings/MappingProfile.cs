using AutoMapper;
using UserAuthentication.Domain.Contracts;
using UserAuthentication.Domain.Entities;

namespace UserAuthentication.Infrastructure.Mappings
{
    public class MappingProfile:Profile
    {
        public MappingProfile()
        {
            CreateMap<ApplicationUser, UserResponse>();
            CreateMap<ApplicationUser,CurrentUserResponse>();
            CreateMap<UserRegisterRequest, ApplicationUser>();
        }
    }
}
